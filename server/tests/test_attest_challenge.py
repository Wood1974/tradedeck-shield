"""The App Attest challenge route: a phone asks for a one-time nonce, then spends it once."""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app.local_identity import LocalIdentity
from app.main import app
from app.store import Store


def test_the_store_hands_out_a_nonce_that_can_be_spent_once_by_its_owner():
    with tempfile.TemporaryDirectory() as td:
        store = Store("sqlite:///" + os.path.join(td, "shield.db"), os.path.join(td, "storage"))
        nonce, expires = store.attestation_challenge("acct-1", 120)
        assert nonce and expires > 0
        with pytest.raises(ValueError, match="attestation_challenge_context_mismatch"):
            store.consume_attestation_challenge(nonce, "acct-2")
        store.consume_attestation_challenge(nonce, "acct-1")
        with pytest.raises(ValueError, match="attestation_nonce_replayed"):
            store.consume_attestation_challenge(nonce, "acct-1")
        with pytest.raises(ValueError, match="unknown_attestation_nonce"):
            store.consume_attestation_challenge("not-a-nonce", "acct-1")


def test_a_signed_in_account_can_ask_for_a_challenge_over_the_api(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", path)
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    LocalIdentity(path).create_account("worker@example.com", "worker-password-123", "capturer")
    client = TestClient(app)
    token = client.post("/shield/auth/login", json={"email": "worker@example.com", "password": "worker-password-123"}).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    first = client.post("/shield/attest/challenge", headers=headers)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["nonce"] and body["expires_at"] > 0
    assert client.post("/shield/attest/challenge", headers=headers).json()["nonce"] != body["nonce"]
    assert client.post("/shield/attest/challenge").status_code == 401


def test_a_registered_key_is_stored_once_and_stays_with_its_account():
    with tempfile.TemporaryDirectory() as td:
        store = Store("sqlite:///" + os.path.join(td, "shield.db"), os.path.join(td, "storage"))
        store.save_attestation_key("key-1", "acct-1", "ZGVy", "production", "cmVjZWlwdA==")
        row = store.get_attestation_key("key-1")
        assert row["account_id"] == "acct-1" and row["counter"] == 0 and row["environment"] == "production"
        store.save_attestation_key("key-1", "acct-1", "ZGVy", "production", "cmVjZWlwdA==")  # the same proof again is fine
        with pytest.raises(ValueError, match="attestation_key_already_bound"):
            store.save_attestation_key("key-1", "acct-2", "ZGVy", "production", "")
