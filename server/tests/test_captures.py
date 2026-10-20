"""Stored photos: what is checked on arrival, who can read them, and that the Python record format matches the phone's."""
import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app import captures, security
from app.local_identity import LocalIdentity
from app.main import app

VECTORS = json.loads((Path(__file__).parent / "vectors" / "capture-record-v1.json").read_text())
PW = "a-long-test-password-1"
b64 = lambda raw: base64.b64encode(raw).decode("ascii")


class Phone:
    """Seals records the way the phone does: canonical bytes, hash link, ECDSA P-256 over the signing message."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public_b64 = b64(self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        self.prev = "a" * 64

    def seal(self, photo: bytes, **overrides):
        record = {"version": 1, "checkpoint_id": "cp-1", "photo_sha256": hashlib.sha256(photo).hexdigest(), "ticket_id": "job-1",
                  "wall_time_ms": 1_700_000_000_000, "monotonic_ms": 5_000, "boot_count": 4, "flags": 0, **overrides}
        record["prev_hash"] = self.prev
        record["record_hash"] = captures.record_hash_of(record, self.prev)
        signature = self.key.sign(captures.signing_message(record, self.prev), ec.ECDSA(hashes.SHA256()))
        self.prev = record["record_hash"]
        return {"record": record, "signature_der_b64": b64(signature), "public_key_uncompressed_b64": self.public_b64, "photo_b64": b64(photo)}


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
    client = TestClient(app)

    class E:
        pass

    e = E()
    e.local, e.client, e.root = local, client, tmp_path / "storage"

    def account(email):
        local.create_account(email, PW, "capturer")
        token = client.post("/shield/auth/login", json={"email": email, "password": PW}).json()["access_token"]
        return {"Authorization": "Bearer " + token}

    e.account = account
    e.alice = account("alice@example.com")
    e.phone = Phone()
    e.upload = lambda body, headers=None: client.post("/shield/captures", json=body, headers=e.alice if headers is None else headers)
    return e


def photo(n=1):
    return bytes([0xFF, 0xD8, 0xFF, 0xE0]) + bytes((i * 7 + n) % 256 for i in range(1999))


def test_the_python_record_format_matches_the_phones_frozen_bytes():
    record = {"version": 1, "checkpoint_id": "cp-1", "photo_sha256": VECTORS["photoSha256"], "ticket_id": "ticket-1",
              "wall_time_ms": 1_700_000_000_000, "monotonic_ms": 5000, "boot_count": 4, "flags": 0}
    assert captures.canonical_bytes(record).decode() == VECTORS["canonicalRequired"]
    assert captures.record_hash_of(record, VECTORS["prevHash"]) == VECTORS["recordHashRequired"]


def test_a_checked_photo_is_stored_listed_and_read_back_identically(env):
    data = photo()
    r = env.upload(env.phone.seal(data))
    assert r.status_code == 200
    body = r.json()
    assert body["already"] is False and body["integrity"] == "verified" and body["attest"] == {"status": "none", "trusted": False}
    listing = env.client.get("/shield/captures", headers=env.alice).json()["captures"]
    assert [c["record_hash"] for c in listing] == [body["record_hash"]]
    back = env.client.get(f"/shield/captures/{body['record_hash']}/photo", headers=env.alice)
    assert back.status_code == 200 and back.content == data and back.headers["content-type"] == "image/jpeg"
    assert "no-store" in back.headers["cache-control"]


def test_uploading_twice_is_safe_and_stores_one(env):
    upload = env.phone.seal(photo())
    assert env.upload(upload).json()["already"] is False
    again = env.upload(upload)
    assert again.status_code == 200 and again.json()["already"] is True
    assert len(env.client.get("/shield/captures", headers=env.alice).json()["captures"]) == 1


def test_a_changed_image_is_refused_and_nothing_is_stored(env):
    upload = env.phone.seal(photo(1))
    upload["photo_b64"] = b64(photo(2))
    r = env.upload(upload)
    assert r.status_code == 422 and r.json()["detail"] == "photo_hash_mismatch"
    assert env.client.get("/shield/captures", headers=env.alice).json()["captures"] == []
    assert not any(env.root.rglob("*.jpg"))


def test_an_edited_record_is_refused(env):
    upload = env.phone.seal(photo())
    upload["record"]["wall_time_ms"] += 1
    assert env.upload(upload).json()["detail"] == "record_hash_mismatch"


def test_a_signature_from_another_key_is_refused(env):
    upload = env.phone.seal(photo())
    upload["public_key_uncompressed_b64"] = Phone().public_b64
    assert env.upload(upload).json()["detail"] == "signature_invalid"


def test_a_field_the_signature_does_not_cover_is_refused(env):
    upload = env.phone.seal(photo())
    upload["record"]["caption"] = "added later"
    assert env.upload(upload).json()["detail"] == "record_invalid"


def test_a_non_canonical_encoding_of_the_image_is_refused(env):
    upload = env.phone.seal(photo())
    for bad in (upload["photo_b64"][:8] + "\n" + upload["photo_b64"][8:], upload["photo_b64"].rstrip("="), ""):
        assert env.upload({**upload, "photo_b64": bad}).json()["detail"] == "photo_invalid"


def test_only_the_account_that_uploaded_can_see_a_photo(env):
    body = env.upload(env.phone.seal(photo())).json()
    bob = env.account("bob@example.com")
    assert env.client.get("/shield/captures", headers=bob).json()["captures"] == []
    assert env.client.get(f"/shield/captures/{body['record_hash']}/photo", headers=bob).status_code == 404
    # The same record uploaded by someone else is a separate copy for that person, never the first person's.
    other = env.upload(env.phone.seal(photo(3)), headers=bob)
    assert other.status_code == 200
    assert env.client.get(f"/shield/captures/{other.json()['record_hash']}/photo", headers=env.alice).status_code == 404


def test_signing_in_is_required(env):
    assert env.upload(env.phone.seal(photo()), headers={}).status_code in (401, 403)
    assert env.client.get("/shield/captures").status_code in (401, 403)


def test_an_account_over_its_quota_is_refused(env, monkeypatch):
    monkeypatch.setenv("SHIELD_ACCOUNT_QUOTA_MB", "0")
    r = env.upload(env.phone.seal(photo()))
    assert r.status_code == 413 and r.json()["detail"] == "quota_exceeded"


def test_an_oversized_photo_is_refused(env, monkeypatch):
    monkeypatch.setenv("SHIELD_MAX_PHOTO_BYTES", "100")
    assert env.upload(env.phone.seal(photo())).status_code == 413


def test_an_assertion_that_cannot_be_checked_is_recorded_and_never_blocks(env):
    upload = {**env.phone.seal(photo()), "app_attest_key_id": "unknown-key", "app_attest_assertion_b64": b64(b"not a real assertion")}
    r = env.upload(upload)
    assert r.status_code == 200
    attest = r.json()["attest"]
    assert attest["trusted"] is False and attest["status"] != "none"


def test_a_stored_file_that_changed_on_disk_is_not_served(env):
    body = env.upload(env.phone.seal(photo())).json()
    next(env.root.rglob("*.jpg")).write_bytes(b"tampered")
    r = env.client.get(f"/shield/captures/{body['record_hash']}/photo", headers=env.alice)
    assert r.status_code == 409 and r.json()["detail"] == "stored_photo_corrupt"


def test_a_record_hash_in_the_url_cannot_reach_other_files(env):
    env.upload(env.phone.seal(photo()))
    for bad in ("..%2F..%2Fshield.db", "not-hex", "A" * 64):
        assert env.client.get(f"/shield/captures/{bad}/photo", headers=env.alice).status_code in (404, 422)
