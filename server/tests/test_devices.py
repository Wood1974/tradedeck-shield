"""Enrolled phones: an account sees only its own, can withdraw one, and a withdrawn key stops counting and cannot be enrolled again."""
import pytest

from app import main
from app.attestation import AttestationVerifier
from app.store import Store
from test_captures import env, photo  # noqa: F401


@pytest.fixture
def keys(env, tmp_path, monkeypatch):
    store = Store(f"sqlite:///{tmp_path / 'store.db'}", str(tmp_path / "evidence"))
    monkeypatch.setattr(main, "store", store)
    store.save_attestation_key("key-a", "alice@example.com", "AAAA", "production", "")
    return store


def alice_id(env):
    return env.client.get("/shield/auth/me", headers=env.alice).json().get("account_id") or env.client.get("/shield/auth/me", headers=env.alice).json().get("id")


def test_lists_only_this_accounts_phones(env, keys):
    me = alice_id(env)
    keys.save_attestation_key("key-mine", me, "BBBB", "production", "")
    keys.save_attestation_key("key-bobs", "someone-else", "CCCC", "production", "")
    got = env.client.get("/shield/devices", headers=env.alice).json()["devices"]
    assert [d["id"] for d in got] == ["key-mine"]
    assert got[0]["revoked_at"] is None and got[0]["photos"] == 0 and got[0]["enrolled_at"].endswith("Z")


def test_requires_sign_in(env, keys):
    assert env.client.get("/shield/devices").status_code in (401, 403)
    assert env.client.post("/shield/devices/revoke", json={"id": "key-a"}).status_code in (401, 403)


def test_revoke_marks_it_and_is_repeatable(env, keys):
    me = alice_id(env)
    keys.save_attestation_key("key-mine", me, "BBBB", "production", "")
    assert env.client.post("/shield/devices/revoke", json={"id": "key-mine"}, headers=env.alice).json() == {"ok": True}
    first = env.client.get("/shield/devices", headers=env.alice).json()["devices"][0]["revoked_at"]
    assert first
    assert env.client.post("/shield/devices/revoke", json={"id": "key-mine"}, headers=env.alice).status_code == 200
    assert env.client.get("/shield/devices", headers=env.alice).json()["devices"][0]["revoked_at"] == first  # the first time is kept


def test_cannot_revoke_someone_elses_or_unknown_key(env, keys):
    assert env.client.post("/shield/devices/revoke", json={"id": "key-a"}, headers=env.alice).status_code == 404
    assert env.client.post("/shield/devices/revoke", json={"id": "nope"}, headers=env.alice).status_code == 404
    assert keys.get_attestation_key("key-a")["revoked_at"] is None
    bob = env.account("bob@example.com")
    me = alice_id(env)
    keys.save_attestation_key("key-mine", me, "BBBB", "production", "")
    assert env.client.post("/shield/devices/revoke", json={"id": "key-mine"}, headers=bob).status_code == 404
    assert keys.get_attestation_key("key-mine")["revoked_at"] is None


def test_bad_bodies(env, keys):
    assert env.client.post("/shield/devices/revoke", json={}, headers=env.alice).status_code == 422
    assert env.client.post("/shield/devices/revoke", json={"id": ""}, headers=env.alice).status_code == 422
    assert env.client.post("/shield/devices/revoke", json={"id": "x" * 500}, headers=env.alice).status_code == 422


def test_a_withdrawn_key_cannot_be_enrolled_again(keys):
    keys.revoke_attestation_key("key-a", "alice@example.com")
    with pytest.raises(ValueError, match="attestation_key_revoked"):
        keys.save_attestation_key("key-a", "alice@example.com", "AAAA", "production", "")


def test_a_withdrawn_key_is_not_trusted_for_new_photos(keys):
    verifier = AttestationVerifier(app_id="766456AWH4.app.tradedeck.shield", mode="production", store=keys)
    keys.revoke_attestation_key("key-a", "alice@example.com")
    # A well-formed but unsigned assertion gets as far as the key lookup: it must stop at the revoked key, not at the signature.
    import base64, cbor2, hashlib, struct
    auth = hashlib.sha256(b"766456AWH4.app.tradedeck.shield").digest() + b"\x00" + struct.pack(">I", 5)
    assertion = base64.b64encode(cbor2.dumps({"authenticatorData": auth, "signature": b"x"})).decode()
    result = verifier.verify_assertion(assertion, "00" * 32, "key-a", account_id="alice@example.com")
    assert result == {"trusted": False, "status": "attestation_key_revoked"}


def test_photos_are_counted_per_phone(env, keys):
    me = alice_id(env)
    keys.save_attestation_key("key-mine", me, "BBBB", "production", "")
    body = env.phone.seal(photo(1))
    body["app_attest_key_id"] = "key-mine"
    env.upload(body)
    assert env.client.get("/shield/devices", headers=env.alice).json()["devices"][0]["photos"] == 1


def test_an_old_database_gets_the_new_column(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE attestation_keys(key_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, public_key_der_b64 TEXT NOT NULL, environment TEXT NOT NULL, counter INTEGER NOT NULL DEFAULT 0, receipt_b64 TEXT, created_at REAL NOT NULL)")
    c.execute("INSERT INTO attestation_keys VALUES('k','a','P','production',3,'',1.0)")
    c.commit(); c.close()
    store = Store(f"sqlite:///{path}", str(tmp_path / "ev"))
    assert store.get_attestation_key("k")["revoked_at"] is None
    assert store.revoke_attestation_key("k", "a") is True
