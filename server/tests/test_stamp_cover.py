"""Which stamp covers which record is written when the stamp is taken, and read by lookup, with the same answers as walking the chain."""
import sqlite3
import uuid

import pytest

from app import captures, outside_time
from app.local_identity import LocalIdentity
from test_captures_speed import account, add_capture, h, naive_coverage


@pytest.fixture
def local(tmp_path):
    return LocalIdentity(f"sqlite:///{tmp_path / 'shield.db'}")


def chain(local, acct, start, end, prev):
    for n in range(start, end + 1):
        add_capture(local, acct, n, prev)
        prev = h(n)
    return prev


def stamp(local, acct, head, gen):
    outside_time._init(local)
    with local.db() as db:
        return outside_time.store_stamp(db, acct, head, "i" * 64, "r", gen, "http://tsa", False, gen)


def test_a_later_stamp_covers_only_what_the_earlier_one_did_not(local):
    acct = account(local)
    chain(local, acct, 1, 4, h(0))
    stamp(local, acct, h(4), 1000.0)
    chain(local, acct, 5, 12, h(4))
    stamp(local, acct, h(12), 2000.0)
    got = {k: v["gen_time"] for k, v in outside_time.coverage(local, acct).items()}
    prev = {h(n): h(n - 1) if n > 1 else h(0) for n in range(1, 13)}
    assert got == naive_coverage(prev, [{"head": h(4), "gen": 1000.0}, {"head": h(12), "gen": 2000.0}])
    assert all(got[h(n)] == 1000.0 for n in range(1, 5)) and all(got[h(n)] == 2000.0 for n in range(5, 13))


def test_a_record_after_the_last_stamp_is_not_covered_and_a_repeat_stamp_is_ignored(local):
    acct = account(local)
    chain(local, acct, 1, 3, h(0))
    assert stamp(local, acct, h(3), 1000.0) is True
    assert stamp(local, acct, h(3), 1500.0) is False  # this head already has its stamp
    chain(local, acct, 4, 5, h(3))
    cov = outside_time.coverage_for(local, acct, [h(n) for n in range(1, 6)])
    assert set(cov) == {h(1), h(2), h(3)}
    assert {v["gen_time"] for v in cov.values()} == {1000.0}


def test_coverage_for_is_one_account_and_the_records_asked_for(local):
    a, b = account(local), account(local)
    chain(local, a, 1, 3, h(0))
    chain(local, b, 101, 103, h(0))
    stamp(local, a, h(3), 1000.0)
    stamp(local, b, h(103), 2000.0)
    assert set(outside_time.coverage_for(local, a, [h(1), h(2), h(101), h(999), None, ""])) == {h(1), h(2)}
    assert outside_time.coverage_for(local, a, []) == {}
    assert {k: v["gen_time"] for k, v in outside_time.coverage_for(local, b, [h(101), h(103)]).items()} == {h(101): 2000.0, h(103): 2000.0}


def test_a_big_account_is_one_lookup_not_a_walk(local, monkeypatch):
    acct = account(local)
    chain(local, acct, 1, 700, h(0))
    stamp(local, acct, h(700), 1000.0)
    everything = [h(n) for n in range(1, 701)]
    assert len(outside_time.coverage_for(local, acct, everything)) == 700  # also crosses the batch size of 500
    opened = []
    real = local.db
    monkeypatch.setattr(local, "db", lambda: (opened.append(1), real())[1])
    outside_time.coverage_for(local, acct, everything[:200])
    assert len(opened) == 1


def test_stamps_taken_before_the_cover_table_existed_are_covered_on_first_use(tmp_path):
    path = tmp_path / "old.db"
    local = LocalIdentity(f"sqlite:///{path}")
    acct = account(local)
    chain(local, acct, 1, 6, h(0))
    # The shape of the table as it was before the cover table: stamps only.
    con = sqlite3.connect(path)
    con.executescript("""CREATE TABLE outside_timestamps (id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES local_accounts(id),
        head_record_hash TEXT NOT NULL, imprint_hex TEXT NOT NULL, reply_b64 TEXT NOT NULL, gen_time REAL NOT NULL, tsa_url TEXT NOT NULL,
        chain_checked INTEGER NOT NULL, created_at REAL NOT NULL, UNIQUE(account_id, head_record_hash));""")
    for head, gen in ((h(3), 1000.0), (h(6), 2000.0)):
        con.execute("INSERT INTO outside_timestamps VALUES(?,?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), acct, head, "i" * 64, "r", gen, "http://tsa", 0, gen))
    con.commit(); con.close()
    got = {k: v["gen_time"] for k, v in outside_time.coverage(local, acct).items()}  # first use sets the tables up and covers
    assert got == {h(1): 1000.0, h(2): 1000.0, h(3): 1000.0, h(4): 2000.0, h(5): 2000.0, h(6): 2000.0}


def test_the_photo_list_shows_the_stamp_through_the_lookup(local):
    acct = account(local)
    chain(local, acct, 1, 3, h(0))
    stamp(local, acct, h(2), 1000.0)
    rows = {r["record_hash"]: r["outside_time"]["status"] for r in captures.list_for(local, acct)}
    assert rows == {h(1): "stamped", h(2): "stamped", h(3): outside_time.view(None)["status"]}
