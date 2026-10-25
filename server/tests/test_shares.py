"""Share codes and the compare-with-server check: privacy, what a match means, and that nothing leaks without a code."""
import hashlib
import json
import sqlite3
import time

import pytest

from app import captures, shares
from test_captures import env, photo, Phone  # noqa: F401  (the fixture and helpers the stored-photo tests use)


@pytest.fixture(autouse=True)
def _fresh_limit():
    shares._compare_times.clear()
    yield
    shares._compare_times.clear()


def stored(env, data=None):
    """Alice uploads a photo; returns its record hash and bytes."""
    data = data if data is not None else photo()
    r = env.upload(env.phone.seal(data))
    assert r.status_code == 200
    return r.json()["record_hash"], data


def make_share(env, record_hash, days=30, headers=None):
    return env.client.post(f"/shield/captures/{record_hash}/share", json={"days": days}, headers=headers if headers is not None else env.alice)


def check(env, code, data, name="photo.jpg"):
    return env.client.post("/shield/v1/compare", data={"code": code}, files={"photo": (name, data, "image/jpeg")})


def test_the_owner_makes_a_code_and_it_is_never_shown_again(env):
    rh, _ = stored(env)
    made = make_share(env, rh)
    assert made.status_code == 200
    body = made.json()
    assert len(shares.normalize(body["code"])) == shares.CODE_LENGTH and set(shares.normalize(body["code"])) <= set(shares.ALPHABET)
    listing = env.client.get(f"/shield/captures/{rh}/shares", headers=env.alice).json()["shares"]
    assert [s["id"] for s in listing] == [body["id"]] and listing[0]["active"] is True
    assert body["code"] not in json.dumps(listing) and "code" not in listing[0]
    with sqlite3.connect(str(env.root.parent / "shield.db")) as db:
        rows = db.execute("SELECT code_hmac FROM capture_shares").fetchall()
    assert rows and shares.normalize(body["code"]) not in rows[0][0]


def test_the_original_file_matches_and_the_answer_carries_no_identity(env):
    rh, data = stored(env)
    code = make_share(env, rh).json()["code"]
    r = check(env, code, data)
    assert r.status_code == 200
    body = r.json()
    assert body["match"] is True
    assert body["checks"] == {"supplied_equals_stored": True, "stored_original_intact": True, "record_signature_valid": True}
    assert set(body) == {"match", "uploaded_at", "checks", "device_check", "uploader", "limitations", "timing"}  # "timing" is only on codes made after it existed (test_check_timing.py)
    text = r.text
    for secret in ("alice@example.com", "cp-1", "job-1", rh, env.phone.public_b64):
        assert secret not in text
    assert body["uploader"] == {"id_check": "not_verified"}


def test_a_recompressed_copy_does_not_match_and_says_why(env):
    rh, data = stored(env)
    code = make_share(env, rh).json()["code"]
    recompressed = data[:-1] + bytes([data[-1] ^ 1])
    r = check(env, code, recompressed)
    assert r.status_code == 200
    body = r.json()
    assert body["match"] is False and body["checks"]["supplied_equals_stored"] is False
    assert "recompressed" in body["hint"] and "original file" in body["hint"]


def test_a_bad_code_of_any_kind_reveals_nothing_and_all_read_the_same(env):
    rh, data = stored(env)
    made = make_share(env, rh).json()
    expired = make_share(env, rh).json()
    revoked = make_share(env, rh).json()
    with sqlite3.connect(str(env.root.parent / "shield.db")) as db:
        db.execute("UPDATE capture_shares SET expires_at=? WHERE id=?", (time.time() - 5, expired["id"]))
    assert env.client.delete(f"/shield/shares/{revoked['id']}", headers=env.alice).status_code == 200
    answers = []
    for code in ("AAAA-BBBB", "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ", expired["code"], revoked["code"], "x"):
        r = check(env, code, data)
        answers.append((r.status_code, r.text))
    assert len(set(answers)) == 1 and answers[0][0] == 404
    assert check(env, made["code"], data).json()["match"] is True


def test_a_file_alone_reveals_nothing(env):
    rh, data = stored(env)
    assert check(env, "", data).status_code in (404, 422)
    assert check(env, "NOPE", data).status_code == 404


def test_codes_ignore_case_spaces_and_dashes(env):
    rh, data = stored(env)
    code = make_share(env, rh).json()["code"]
    assert check(env, code.lower().replace("-", " "), data).json()["match"] is True


def test_only_the_owner_can_make_list_or_withdraw_a_code(env):
    rh, _ = stored(env)
    bob = env.account("bob@example.com")
    assert make_share(env, rh, headers=bob).status_code == 404
    assert env.client.get(f"/shield/captures/{rh}/shares", headers=bob).status_code == 404
    made = make_share(env, rh).json()
    assert env.client.delete(f"/shield/shares/{made['id']}", headers=bob).status_code == 404
    assert env.client.post(f"/shield/captures/{rh}/share", json={"days": 5}).status_code in (401, 403)
    assert make_share(env, "0" * 64).status_code == 404
    assert make_share(env, "not-a-hash").status_code == 404


def test_a_withdrawn_code_stops_working(env):
    rh, data = stored(env)
    made = make_share(env, rh).json()
    assert check(env, made["code"], data).json()["match"] is True
    assert env.client.delete(f"/shield/shares/{made['id']}", headers=env.alice).status_code == 200
    assert check(env, made["code"], data).status_code == 404
    assert env.client.delete(f"/shield/shares/{made['id']}", headers=env.alice).status_code == 404


def test_the_lifetime_is_limited(env):
    rh, _ = stored(env)
    assert make_share(env, rh, days=0).status_code == 422
    assert make_share(env, rh, days=shares.MAX_DAYS + 1).status_code == 422
    assert make_share(env, rh, days=shares.MAX_DAYS).status_code == 200


def test_a_stored_file_changed_on_disk_is_not_called_a_match(env):
    rh, data = stored(env)
    code = make_share(env, rh).json()["code"]
    path = next(env.root.rglob(f"{rh}.jpg"))
    path.write_bytes(data[:-1] + b"\x00")
    body = check(env, code, data).json()
    assert body["match"] is False
    assert body["checks"]["supplied_equals_stored"] is True and body["checks"]["stored_original_intact"] is False


def test_the_uploader_status_is_only_whether_the_id_check_passed(env):
    from app.identity_api import _db
    rh, data = stored(env)
    code = make_share(env, rh).json()["code"]
    account_id = env.client.get("/shield/auth/me", headers=env.alice).json()["account_id"]
    verified = time.time() - 3600
    with _db() as db:
        db.execute("INSERT INTO identity_sessions(id,account_id,stripe_session_id,status,livemode,consent_at,consent_version,created_at,verified_at) "
                   "VALUES('s1',?,?,?,1,?,'1',?,?)", (account_id, "vs_1", "verified", verified, verified, verified))
    assert check(env, code, data).json()["uploader"] == {"id_check": "not_verified"}  # no signed note yet
    with _db() as db:
        db.execute("INSERT INTO note_attestations(id,account_id,session_id,device_seal_id,device_public_key,statement_version,note_payload,note_sha256,signature,signed_at,receipt,created_at) "
                   "VALUES('n1',?,'s1','seal','pk','1','{}','h1','sig','now','r',?)", (account_id, verified))
    up = check(env, code, data).json()["uploader"]
    assert up["id_check"] == "passed" and up["before_upload"] is True and len(up["on"]) == 10
    assert "name" not in up and "account" not in json.dumps(up)
    with _db() as db:
        db.execute("UPDATE identity_sessions SET livemode=0 WHERE id='s1'")
    assert check(env, code, data).json()["uploader"]["id_check"] == "test_mode"


def test_each_check_is_logged_in_a_hash_chain_without_the_file_or_address(env):
    rh, data = stored(env)
    code = make_share(env, rh).json()["code"]
    check(env, code, data)
    check(env, code, data[:-1] + b"\x01")
    with sqlite3.connect(str(env.root.parent / "shield.db")) as db:
        rows = db.execute("SELECT result, previous_hash, event_hash FROM compare_log ORDER BY rowid").fetchall()
    assert [r[0] for r in rows] == ["match", "no_match"]
    assert rows[0][1] is None and rows[1][1] == rows[0][2] and rows[0][2] != rows[1][2]


def test_size_and_flood_limits(env, monkeypatch):
    rh, data = stored(env)
    code = make_share(env, rh).json()["code"]
    monkeypatch.setattr("app.main.MAX_PHOTO_BYTES", 10)
    assert check(env, code, data).status_code == 413
    assert check(env, code, b"").status_code == 400
    monkeypatch.setattr("app.main.MAX_PHOTO_BYTES", 15 * 1024 * 1024)
    monkeypatch.setattr(shares, "HOURLY_COMPARE_LIMIT", 2)
    shares._compare_times.clear()
    assert check(env, code, data).status_code == 200 and check(env, code, data).status_code == 200
    assert check(env, code, data).status_code == 429


def test_a_share_for_one_account_cannot_reach_another_accounts_photo(env):
    rh_a, data_a = stored(env, photo(1))
    bob = env.account("bob@example.com")
    phone_b = Phone()
    body = env.client.post("/shield/captures", json=phone_b.seal(photo(2)), headers=bob).json()
    code_b = make_share(env, body["record_hash"], headers=bob).json()["code"]
    assert check(env, code_b, photo(1)).json()["match"] is False   # Alice's file is not Bob's stored photo
    assert check(env, code_b, photo(2)).json()["match"] is True
