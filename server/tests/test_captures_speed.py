"""The photo list does a fixed number of queries, and the faster paths give the same answers as the plain ones."""
import json
import random
import uuid

import pytest

from app import captures, outside_time, tickets
from app.local_identity import LocalIdentity


@pytest.fixture
def local(tmp_path):
    return LocalIdentity(f"sqlite:///{tmp_path / 'shield.db'}")


def account(local):
    return local.create_account(f"{uuid.uuid4().hex[:8]}@example.com", "a-long-enough-password-1", "capturer").id


def h(n: int) -> str:
    return f"{n:064x}"


def add_capture(local, account_id, n, prev, ticket_hash=None, received=None):
    captures._init(local)
    with local.db() as db:
        db.execute(
            "INSERT INTO captures(id,account_id,record_hash,prev_hash,ticket_id,checkpoint_id,photo_sha256,photo_bytes,record_json,"
            "signature_der_b64,public_key_b64,attest_status,attest_trusted,received_at,ticket_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), account_id, h(n), prev, "job", "cp", h(10_000 + n), 1, "{}", "s", "k", "none", 0, received or float(n), ticket_hash))


def add_ticket(local, account_id, n):
    tickets._init(local)
    with local.db() as db:
        db.execute(
            "INSERT INTO tickets(id,account_id,ticket_id,ticket_hash,ticket_json,kid,clock_json,public_key_b64,device_signature_b64,"
            "server_time_ms,countersigned_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), account_id, f"t{n}", h(50_000 + n), "{}", "kid", json.dumps({"wall_time_ms": n}), "k", "s", 1000 + n, 2000 + n))


def naive_coverage(prev, stamps):
    """The plain walk: every stamp, oldest first, all the way back, keeping the first stamp to reach a record."""
    out = {}
    for s in stamps:
        x, hops = s["head"], 0
        while x in prev and hops < 100_000:
            out.setdefault(x, s["gen"])
            x, hops = prev[x], hops + 1
    return out


def test_stamp_coverage_matches_the_plain_walk_on_random_chains(local):
    rnd = random.Random(7)
    for trial in range(25):
        acct = account(local)
        base = trial * 1000
        n = rnd.randint(1, 40)
        prev_of = {}
        last = h(0)
        for i in range(1, n + 1):
            add_capture(local, acct, base + i, last)
            prev_of[h(base + i)] = last
            last = h(base + i)
        # a second chain branching from a random earlier record, so a stamp can sit on a side branch
        branch_from = h(base + rnd.randint(1, n))
        for j in range(1, rnd.randint(1, 8)):
            add_capture(local, acct, base + 500 + j, branch_from)
            prev_of[h(base + 500 + j)] = branch_from
            branch_from = h(base + 500 + j)
        heads = rnd.sample(sorted(prev_of), k=min(len(prev_of), rnd.randint(0, 6)))
        outside_time._init(local)
        stamps = []
        with local.db() as db:
            for k, head in enumerate(heads):
                gen = 1000.0 + k
                outside_time.store_stamp(db, acct, head, "i" * 64, "r", gen, "http://tsa", False, gen)
                stamps.append({"head": head, "gen": gen})
        got = {k: v["gen_time"] for k, v in outside_time.coverage(local, acct).items()}
        assert got == naive_coverage(prev_of, sorted(stamps, key=lambda s: s["gen"]))


def test_by_hashes_matches_by_hash_including_misses_and_big_batches(local):
    acct, other = account(local), account(local)
    for n in range(620):
        add_ticket(local, acct, n)
    add_ticket(local, other, 9_999)
    asked = [h(50_000 + n) for n in range(620)] + [h(1), h(50_000 + 9_999), None, ""]
    many = tickets.by_hashes(local, acct, asked)
    assert set(many) == {h(50_000 + n) for n in range(620)}  # not another account's, not a missing one
    for hash_hex in (h(50_000 + 0), h(50_000 + 619), h(1), h(50_000 + 9_999)):
        assert many.get(hash_hex) == tickets.by_hash(local, acct, hash_hex)
    assert tickets.by_hashes(local, acct, []) == {} and tickets.by_hashes(local, acct, [None]) == {}


def test_listing_fifty_photos_opens_a_fixed_number_of_connections(local, monkeypatch):
    acct = account(local)
    prev = h(0)
    for n in range(1, 51):
        add_ticket(local, acct, n)
        add_capture(local, acct, n, prev, ticket_hash=h(50_000 + n))
        prev = h(n)
    captures.list_for(local, acct)  # first call also creates the tables
    opened = []
    real = local.db
    monkeypatch.setattr(local, "db", lambda: (opened.append(1), real())[1])
    rows = captures.list_for(local, acct)
    assert len(rows) == 50 and all(r["ticket"]["origin"] == "server" for r in rows)
    assert len(opened) <= 4, f"{len(opened)} connections for 50 photos"


def test_table_setup_runs_once_per_database_file(local, tmp_path, monkeypatch):
    captures._init(local)
    opened = []
    real = local.db
    monkeypatch.setattr(local, "db", lambda: (opened.append(1), real())[1])
    captures._init(local)
    assert opened == []  # already set up: no connection at all
    other = LocalIdentity(f"sqlite:///{tmp_path / 'other.db'}")  # a different file is set up on its own
    captures._init(other)
    with other.db() as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE name='captures'").fetchone()


def test_the_account_and_time_index_exists_and_is_used(local):
    captures._init(local)
    with local.db() as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE name='captures_account_received'").fetchone()
        plan = " ".join(r[3] for r in db.execute("EXPLAIN QUERY PLAN SELECT * FROM captures WHERE account_id=? ORDER BY received_at DESC LIMIT 200", ("x",)))
    assert "captures_account_received" in plan and "TEMP B-TREE" not in plan
