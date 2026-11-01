"""The clock check: what a photo's own clocks can and cannot say, and that it never blocks a photo."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import captures, security, time_audit
from app.local_identity import LocalIdentity
from app.main import app
from test_captures import PW, Phone, photo

L = time_audit.LIMIT_MS
NOW = 1_700_000_100_000


def rec(wall=1_700_000_000_000, mono=5_000, boot_count=4, **extra):
    r = {"wall_time_ms": wall, "monotonic_ms": mono, "boot_count": boot_count}
    r.update(extra)
    return r


def label(record, previous=None, received=NOW):
    return time_audit.assess(record, previous, received)["label"]


def test_the_wall_clock_moving_with_the_monotonic_clock_is_consistent():
    before = rec(wall=1_700_000_000_000, mono=5_000)
    assert label(rec(wall=1_700_000_060_000, mono=65_000), before) == time_audit.CONSISTENT


@pytest.mark.parametrize("extra,expected", [(L, time_audit.CONSISTENT), (L + 1, time_audit.MISMATCH), (-L, time_audit.CONSISTENT), (-L - 1, time_audit.MISMATCH)])
def test_the_limit_is_strict_in_both_directions(extra, expected):
    before = rec(wall=1_700_000_000_000, mono=5_000)
    assert label(rec(wall=1_700_000_060_000 + extra, mono=65_000), before) == expected


def test_a_restart_between_two_photos_is_unverified_not_a_mismatch():
    before = rec(boot_count=4)
    after = rec(wall=1_700_000_000_000 + 9 * 3600_000, mono=1_000, boot_count=5)
    out = time_audit.assess(after, before, NOW + 10 * 3600_000)
    assert out["label"] == time_audit.UNVERIFIED
    assert any("restart" in n for n in out["notes"])


def test_boot_id_is_used_when_there_is_one():
    assert label(rec(boot_id="a", boot_count=None, wall=1_700_000_010_000, mono=15_000), rec(boot_id="a", boot_count=None)) == time_audit.CONSISTENT
    assert label(rec(boot_id="b", boot_count=None, mono=15_000), rec(boot_id="a", boot_count=None)) == time_audit.UNVERIFIED


def test_a_record_that_does_not_say_which_boot_it_is_from_is_unverified():
    assert label(rec(boot_count=None, mono=15_000), rec()) == time_audit.UNVERIFIED


def test_a_monotonic_clock_running_backward_is_unverified():
    assert label(rec(wall=1_700_000_010_000, mono=1_000), rec(mono=5_000)) == time_audit.UNVERIFIED


def test_changing_the_wall_clock_across_a_restart_does_not_turn_into_a_mismatch():
    assert label(rec(wall=1_800_000_000_000, mono=100, boot_count=9), rec(), received=1_800_000_000_500) == time_audit.UNVERIFIED


def test_gps_time_agreeing_makes_a_first_record_consistent_and_disagreeing_is_a_mismatch():
    assert label(rec(gnss_time_ms=1_700_000_000_000 + L)) == time_audit.CONSISTENT
    assert label(rec(gnss_time_ms=1_700_000_000_000 + L + 1)) == time_audit.MISMATCH
    assert label(rec(gnss_time_ms=1_700_000_000_000 - L - 1)) == time_audit.MISMATCH


def test_a_first_record_with_nothing_to_compare_is_not_checked():
    out = time_audit.assess(rec(), None, NOW)
    assert out["label"] == time_audit.NOT_CHECKED and out["notes"]


def test_a_phone_clock_ahead_of_the_server_is_a_mismatch_but_a_long_wait_is_not():
    assert label(rec(wall=NOW + L + 1)) == time_audit.MISMATCH
    assert label(rec(wall=NOW + L, gnss_time_ms=NOW + L)) == time_audit.CONSISTENT
    assert label(rec(wall=NOW - 30 * 86400_000, gnss_time_ms=NOW - 30 * 86400_000)) == time_audit.CONSISTENT  # waited a month for signal


def test_the_server_clock_check_alone_never_earns_consistent():
    assert label(rec(wall=NOW - 1000)) == time_audit.NOT_CHECKED


def test_one_disagreement_outranks_agreement_elsewhere():
    before = rec()
    assert label(rec(wall=1_700_000_060_000, mono=65_000, gnss_time_ms=1_700_000_060_000 + L + 1), before) == time_audit.MISMATCH


def test_unverified_outranks_a_passing_gps_time():
    assert label(rec(boot_count=5, gnss_time_ms=1_700_000_000_000), rec(boot_count=4)) == time_audit.UNVERIFIED


# --- through a real upload -------------------------------------------------------------------------------------------

@pytest.fixture
def env(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", path)
    monkeypatch.setenv("SHIELD_STORAGE_ROOT", str(tmp_path / "storage"))
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    security._BUCKETS.clear()
    local = LocalIdentity(path)
    local.create_account("alice@example.com", PW, "capturer")
    client = TestClient(app)
    token = client.post("/shield/auth/login", json={"email": "alice@example.com", "password": PW}).json()["access_token"]

    class E:
        pass

    e = E()
    e.client, e.local, e.path, e.alice = client, local, tmp_path / "shield.db", {"Authorization": "Bearer " + token}
    return e


def time_of(env, item):
    listed = env.client.get("/shield/captures", headers=env.alice).json()["captures"]
    return next(c["time"] for c in listed if c["record_hash"] == item["record"]["record_hash"])


def test_a_chain_of_uploads_is_checked_against_the_record_before_it(env):
    phone = Phone()
    base = 1_700_000_000_000
    first = phone.seal(photo(1), wall_time_ms=base, monotonic_ms=5_000)
    second = phone.seal(photo(2), wall_time_ms=base + 60_000, monotonic_ms=65_000)
    skewed = phone.seal(photo(3), wall_time_ms=base + 60_000 + 3_600_000, monotonic_ms=125_000)
    for item in (first, second, skewed):
        assert env.client.post("/shield/captures", json=item, headers=env.alice).status_code == 200
    assert time_of(env, first)["label"] == time_audit.NOT_CHECKED
    assert time_of(env, second)["label"] == time_audit.CONSISTENT
    out = time_of(env, skewed)
    assert out["label"] == time_audit.MISMATCH and out["notes"]


def test_a_mismatch_never_blocks_the_photo(env):
    phone = Phone()
    future = phone.seal(photo(1), wall_time_ms=4_000_000_000_000)  # the year 2096
    r = env.client.post("/shield/captures", json=future, headers=env.alice)
    assert r.status_code == 200
    assert r.json()["time"]["label"] == time_audit.MISMATCH


def test_a_record_whose_predecessor_is_not_on_the_server_is_not_checked_rather_than_guessed(env):
    phone = Phone()
    phone.seal(photo(1))                 # sealed but never uploaded
    later = phone.seal(photo(2), monotonic_ms=65_000)
    env.client.post("/shield/captures", json=later, headers=env.alice)
    assert time_of(env, later)["label"] == time_audit.NOT_CHECKED


def test_a_table_made_before_the_clock_check_is_upgraded_and_old_rows_say_so(env):
    db = sqlite3.connect(env.path)
    db.executescript("""
      DROP TABLE IF EXISTS captures;
      CREATE TABLE captures (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, record_hash TEXT NOT NULL, prev_hash TEXT NOT NULL,
        ticket_id TEXT NOT NULL, checkpoint_id TEXT NOT NULL, photo_sha256 TEXT NOT NULL, photo_bytes INTEGER NOT NULL,
        record_json TEXT NOT NULL, signature_der_b64 TEXT NOT NULL, public_key_b64 TEXT NOT NULL, attest_key_id TEXT,
        attest_status TEXT NOT NULL, attest_trusted INTEGER NOT NULL DEFAULT 0, received_at REAL NOT NULL, UNIQUE(account_id, record_hash));
    """)
    account = db.execute("SELECT id FROM local_accounts").fetchone()[0]
    db.execute("INSERT INTO captures VALUES('x',?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (account, "a" * 64, "b" * 64, "t", "c", "d" * 64, 1, "{}", "s", "k", None, "none", 0, 1.0))
    db.commit()
    db.close()
    listed = env.client.get("/shield/captures", headers=env.alice).json()["captures"]
    assert listed[0]["time"] == {"label": time_audit.NOT_CHECKED, "notes": ["stored before the clock check existed"]}
    item = Phone().seal(photo(9))
    assert env.client.post("/shield/captures", json=item, headers=env.alice).status_code == 200


# --- a clock set back before the chain began (found by running the checker, not by reading it) ---
DAY = 86_400_000


def _rec(wall, mono, **extra):
    return {"wall_time_ms": wall, "monotonic_ms": mono, "boot_id": "b1", "boot_count": 7, **extra}


def test_a_clock_set_back_before_the_chain_still_reads_consistent_but_never_claims_the_date():
    now = 1_790_000_000_000
    first, second = _rec(now - 2 * DAY, 1_000_000), _rec(now - 2 * DAY + 60_000, 1_060_000)
    got = time_audit.assess(second, first, now)
    assert got["label"] == time_audit.CONSISTENT  # honest: the phone's own clocks do agree
    text = " ".join(got["notes"])
    assert "the phone's word" in text and "no server ticket" in text
    assert "2 days before it uploaded" in text


def test_a_server_ticket_at_the_start_removes_the_phones_word_notes():
    now = 1_790_000_000_000
    first, second = _rec(now - 60_000, 1_000_000), _rec(now - 1_000, 1_059_000)
    assert time_audit.assess(second, first, now, anchored=True) == {"label": time_audit.CONSISTENT, "notes": []}
    assert "phone's word" in " ".join(time_audit.assess(second, first, now)["notes"])


def test_old_photos_are_not_flagged_as_a_mismatch_just_for_waiting_for_signal():
    now = 1_790_000_000_000
    got = time_audit.assess(_rec(now - 3 * DAY, 5), None, now)
    assert got["label"] == time_audit.NOT_CHECKED and "3 days before" in " ".join(got["notes"])
