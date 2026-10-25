"""Password hashes move to the stronger scrypt setting the next time their owner signs in, and nothing else changes."""
import hashlib
import secrets
import sqlite3
import time
import uuid

import pytest

from app import local_identity
from app.local_identity import CURRENT_KDF, LEGACY_KDF, LocalIdentity

REAL = dict(local_identity.KDF_PARAMS)  # read at import, before the fixture swaps in cheap settings
PW = "a-long-enough-password-1"


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    return LocalIdentity(f"sqlite:///{tmp_path / 'shield.db'}")


def legacy_account(local, email="old@example.com", password=PW):
    """An account exactly as the server made them before the upgrade: legacy hash, NULL kdf column."""
    salt = secrets.token_bytes(16)
    with local.db() as db:
        db.execute("INSERT INTO local_accounts(id,email,password_salt,password_hash,password_kdf,role,created_at) VALUES(?,?,?,?,?,?,?)",
                   (str(uuid.uuid4()), email, salt.hex(), LocalIdentity._digest(password, salt, LEGACY_KDF), None, "capturer", time.time()))
    return email


def row(local, email):
    with local.db() as db:
        return db.execute("SELECT * FROM local_accounts WHERE email=?", (email,)).fetchone()


def test_the_real_settings_are_the_ones_chosen():
    assert REAL == {"scrypt-14-8-1": (2**14, 8, 1), "scrypt-15-8-3": (2**15, 8, 3)}
    assert LEGACY_KDF == "scrypt-14-8-1" and CURRENT_KDF == "scrypt-15-8-3"
    assert 128 * 2**15 * 8 <= local_identity.MAX_SCRYPT_MEMORY  # the stronger setting fits the memory limit given to scrypt


def test_a_sign_in_with_the_real_settings_works_end_to_end(local, monkeypatch):
    monkeypatch.setattr(local_identity, "KDF_PARAMS", REAL)
    acct = local.create_account("real@example.com", PW)
    assert local.authenticate("real@example.com", PW).id == acct.id
    assert local.authenticate("real@example.com", PW + "x") is None
    legacy_hash = hashlib.scrypt(PW.encode(), salt=bytes.fromhex(row(local, "real@example.com")["password_salt"]), n=2**15, r=8, p=3, maxmem=64 * 2**20).hex()
    assert row(local, "real@example.com")["password_hash"] == legacy_hash  # stored as the stronger setting


def test_new_accounts_and_resets_use_the_current_setting(local):
    acct = local.create_account("new@example.com", PW)
    assert row(local, "new@example.com")["password_kdf"] == CURRENT_KDF
    legacy_account(local)
    old = row(local, "old@example.com")
    local.reset_password(old["id"], "another-long-password-2")
    after = row(local, "old@example.com")
    assert after["password_kdf"] == CURRENT_KDF and after["auth_version"] == old["auth_version"] + 1
    assert local.authenticate("old@example.com", "another-long-password-2") is not None and local.authenticate("old@example.com", PW) is None


def test_a_legacy_account_signs_in_and_is_upgraded_without_a_new_password(local):
    legacy_account(local)
    before = row(local, "old@example.com")
    assert before["password_kdf"] is None
    token = local.token(local.authenticate("old@example.com", PW))
    after = row(local, "old@example.com")
    assert after["password_kdf"] == CURRENT_KDF and after["password_hash"] != before["password_hash"]
    assert after["password_salt"] == before["password_salt"] and after["auth_version"] == before["auth_version"]
    assert local.verify(token).email == "old@example.com"  # tokens made before the upgrade keep working
    assert local.authenticate("old@example.com", PW) is not None  # and the next sign-in uses the new hash
    assert local.authenticate("old@example.com", PW + "x") is None


def test_a_wrong_password_or_an_inactive_account_is_not_upgraded(local):
    legacy_account(local)
    assert local.authenticate("old@example.com", "wrong-password-123") is None
    assert row(local, "old@example.com")["password_kdf"] is None
    with local.db() as db:
        db.execute("UPDATE local_accounts SET active=0 WHERE email='old@example.com'")
    assert local.authenticate("old@example.com", PW) is None
    assert row(local, "old@example.com")["password_kdf"] is None


def test_a_reset_that_lands_during_sign_in_is_not_overwritten(local, monkeypatch):
    legacy_account(local)
    acct_id = row(local, "old@example.com")["id"]
    real_compare = local_identity.hmac.compare_digest

    def reset_then_compare(a, b):
        local.reset_password(acct_id, "the-new-password-after-reset")  # lands between the check and the upgrade
        monkeypatch.setattr(local_identity.hmac, "compare_digest", real_compare)
        return True

    monkeypatch.setattr(local_identity.hmac, "compare_digest", reset_then_compare)
    local.authenticate("old@example.com", PW)
    assert local.authenticate("old@example.com", "the-new-password-after-reset") is not None
    assert local.authenticate("old@example.com", PW) is None


def test_every_attempt_does_the_same_two_hashes(local, monkeypatch):
    legacy_account(local)
    local.create_account("new@example.com", PW)
    calls = []
    real = LocalIdentity._digest
    monkeypatch.setattr(LocalIdentity, "_digest", staticmethod(lambda pw, salt, kdf=CURRENT_KDF: (calls.append(kdf), real(pw, salt, kdf))[1]))
    for email in ("old@example.com", "new@example.com", "nobody@example.com"):
        calls.clear()
        local.authenticate(email, PW)
        assert sorted(calls) == sorted([LEGACY_KDF, CURRENT_KDF]), email


def test_a_table_made_before_the_upgrade_gets_the_column_and_keeps_its_hashes(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("""CREATE TABLE local_accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin','capturer')), active INTEGER NOT NULL DEFAULT 1,
        auth_version INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);""")
    salt = secrets.token_bytes(16)
    con.execute("INSERT INTO local_accounts VALUES('1','a@example.com',?,?,'capturer',1,1,0)", (salt.hex(), LocalIdentity._digest(PW, salt, LEGACY_KDF)))
    con.commit(); con.close()
    old = LocalIdentity(f"sqlite:///{path}")
    assert row(old, "a@example.com")["password_kdf"] is None
    assert old.authenticate("a@example.com", PW).email == "a@example.com"
    assert row(old, "a@example.com")["password_kdf"] == CURRENT_KDF
