"""Server-signed job tickets: the handshake, what it anchors, and every way it can be refused."""
import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app import security, tickets, time_audit
from app.local_identity import LocalIdentity
from app.main import app
from test_captures import PW, Phone, photo

VECTORS = json.loads((Path(__file__).parent / "vectors" / "capture-record-v1.json").read_text())
b64 = lambda raw: base64.b64encode(raw).decode("ascii")
sign = lambda key, data: b64(key.sign(data, ec.ECDSA(hashes.SHA256())))


def pem() -> str:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


@pytest.fixture
def env(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", path)
    monkeypatch.setenv("SHIELD_STORAGE_ROOT", str(tmp_path / "storage"))
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("SHIELD_TICKET_SIGNING_KEY_PEM", pem())
    security._BUCKETS.clear()
    local = LocalIdentity(path)
    client = TestClient(app)

    def account(email):
        local.create_account(email, PW, "capturer")
        token = client.post("/shield/auth/login", json={"email": email, "password": PW}).json()["access_token"]
        with local.db() as db:
            return {"Authorization": "Bearer " + token}, db.execute("SELECT id FROM local_accounts WHERE email=?", (email,)).fetchone()[0]

    class E:
        pass

    e = E()
    e.client, e.local, e.monkeypatch = client, local, monkeypatch
    e.alice, e.alice_id = account("alice@example.com")
    e.bob, e.bob_id = account("bob@example.com")
    return e


CLOCK = {"wall_time_ms": 1_700_000_000_000, "monotonic_ms": 5_000, "boot_count": 4}


def start(env, phone, ticket_id="job-1", headers=None, clock=CLOCK):
    """The whole handshake as the phone does it. Returns (ticket_hash, countersign response)."""
    headers = headers or env.alice
    issued = env.client.post("/shield/tickets", json={"ticket_id": ticket_id}, headers=headers).json()
    body = {"ticket": issued["ticket"], "server_signature_der_b64": issued["server_signature_der_b64"], "ticket_clock": clock,
            "signature_der_b64": sign(phone.key, tickets.genesis_client_data(issued["ticket_hash"], clock)),
            "public_key_uncompressed_b64": phone.public_b64}
    return issued["ticket_hash"], env.client.post("/shield/tickets/countersign", json=body, headers=headers), body


def listed(env, headers=None):
    return {c["record_hash"]: c for c in env.client.get("/shield/captures", headers=headers or env.alice).json()["captures"]}


def test_the_genesis_payload_matches_the_phones_frozen_bytes():
    clock = {"boot_count": 4, "monotonic_ms": 5000, "wall_time_ms": 1_700_000_000_000}
    assert tickets.clock_bytes(clock).decode() == VECTORS["ticketClockBytes"]
    assert tickets.genesis_payload(VECTORS["ticketHashHex"], clock).hex() == VECTORS["genesisPayloadSha256"]


def test_the_handshake_stores_a_start_and_the_published_key_checks_the_ticket(env):
    phone = Phone()
    h, r, body = start(env, phone)
    assert r.status_code == 200 and r.json() == {"ticket_hash": h, "started": True, "already": False}
    info = env.client.get("/shield/tickets/key").json()
    assert info["kid"] == body["ticket"]["kid"]
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(info["public_key_uncompressed_b64"]))
    public.verify(base64.b64decode(body["server_signature_der_b64"]), tickets.canonical(body["ticket"]), ec.ECDSA(hashes.SHA256()))  # raises if wrong
    assert body["ticket"]["account_id"] == env.alice_id


def test_a_chain_started_with_a_ticket_is_anchored_and_its_first_photo_is_checked_against_the_ticket_clock(env):
    phone = Phone()
    h, r, _ = start(env, phone)
    phone.prev = h
    first = phone.seal(photo(1), ticket_id="job-1", wall_time_ms=1_700_000_060_000, monotonic_ms=65_000, boot_count=4)
    second = phone.seal(photo(2), ticket_id="job-1", wall_time_ms=1_700_000_120_000, monotonic_ms=125_000, boot_count=4)
    for item in (first, second):
        assert env.client.post("/shield/captures", json=item, headers=env.alice).status_code == 200
    rows = listed(env)
    for item in (first, second):
        c = rows[item["record"]["record_hash"]]
        assert c["ticket"]["origin"] == "server" and c["ticket"]["after"] <= c["ticket"]["before"]
        assert c["time"]["label"] == time_audit.CONSISTENT


def test_a_first_photo_whose_clock_disagrees_with_the_ticket_clock_is_flagged(env):
    phone = Phone()
    h, _, _ = start(env, phone)
    phone.prev = h
    jumped = phone.seal(photo(1), ticket_id="job-1", wall_time_ms=1_700_000_060_000 + 3_600_000, monotonic_ms=65_000, boot_count=4)
    assert env.client.post("/shield/captures", json=jumped, headers=env.alice).status_code == 200
    assert listed(env)[jumped["record"]["record_hash"]]["time"]["label"] == time_audit.MISMATCH


def test_a_ticket_only_anchors_records_for_its_own_ticket_id_and_account(env):
    phone = Phone()
    h, _, _ = start(env, phone, ticket_id="job-1")
    phone.prev = h
    other_job = phone.seal(photo(1), ticket_id="job-2")
    assert env.client.post("/shield/captures", json=other_job, headers=env.alice).status_code == 200
    assert listed(env)[other_job["record"]["record_hash"]]["ticket"] == {"origin": "local"}
    thief = Phone()
    thief.prev = h
    stolen = thief.seal(photo(2), ticket_id="job-1")
    assert env.client.post("/shield/captures", json=stolen, headers=env.bob).status_code == 200
    assert listed(env, env.bob)[stolen["record"]["record_hash"]]["ticket"] == {"origin": "local"}


def test_a_chain_with_no_ticket_says_local(env):
    phone = Phone()
    item = phone.seal(photo(1))
    env.client.post("/shield/captures", json=item, headers=env.alice)
    assert listed(env)[item["record"]["record_hash"]]["ticket"] == {"origin": "local"}


def test_without_a_signing_key_everything_is_closed_and_uploads_still_work(env):
    env.monkeypatch.delenv("SHIELD_TICKET_SIGNING_KEY_PEM")
    assert env.client.get("/shield/tickets/key").status_code == 503
    r = env.client.post("/shield/tickets", json={"ticket_id": "job-1"}, headers=env.alice)
    assert r.status_code == 503 and r.json()["detail"] == "tickets_closed"
    assert env.client.post("/shield/tickets/countersign", json={"ticket": {}, "server_signature_der_b64": "", "ticket_clock": {}, "signature_der_b64": "", "public_key_uncompressed_b64": ""}, headers=env.alice).status_code == 503
    assert env.client.post("/shield/captures", json=Phone().seal(photo(1)), headers=env.alice).status_code == 200


def test_a_key_that_is_not_a_p256_private_key_is_closed_not_a_crash(env):
    env.monkeypatch.setenv("SHIELD_TICKET_SIGNING_KEY_PEM", "not a key")
    assert env.client.post("/shield/tickets", json={"ticket_id": "job-1"}, headers=env.alice).json()["detail"] == "ticket_key_invalid"
    other = ec.generate_private_key(ec.SECP384R1()).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    env.monkeypatch.setenv("SHIELD_TICKET_SIGNING_KEY_PEM", other)
    assert env.client.post("/shield/tickets", json={"ticket_id": "job-1"}, headers=env.alice).status_code == 503


def refused(env, body, code, status=422, headers=None):
    r = env.client.post("/shield/tickets/countersign", json=body, headers=headers or env.alice)
    assert r.status_code == status and r.json()["detail"] == code, r.text


def test_every_way_the_handshake_can_go_wrong_is_refused_with_a_reason(env):
    phone = Phone()
    _, _, good = start(env, phone, ticket_id="job-0")  # a ticket id already used; the copies below start fresh ones
    issued = env.client.post("/shield/tickets", json={"ticket_id": "job-1"}, headers=env.alice).json()
    base = {"ticket": issued["ticket"], "server_signature_der_b64": issued["server_signature_der_b64"], "ticket_clock": CLOCK,
            "signature_der_b64": sign(phone.key, tickets.genesis_client_data(issued["ticket_hash"], CLOCK)), "public_key_uncompressed_b64": phone.public_b64}

    refused(env, base, "ticket_for_another_account", headers=env.bob)
    tampered = json.loads(json.dumps(base))
    tampered["ticket"]["expires_at_ms"] += 1
    refused(env, tampered, "ticket_signature_invalid")
    extra = json.loads(json.dumps(base))
    extra["ticket"]["note"] = "added"
    refused(env, extra, "ticket_invalid")
    refused(env, {**base, "ticket_clock": {**CLOCK, "wall_time_ms": CLOCK["wall_time_ms"] + 1}}, "device_signature_invalid")
    refused(env, {**base, "public_key_uncompressed_b64": Phone().public_b64}, "device_signature_invalid")
    refused(env, {**base, "signature_der_b64": "!!!"}, "device_signature_invalid")
    refused(env, {**base, "server_signature_der_b64": "!!!"}, "ticket_signature_invalid")
    refused(env, {**base, "ticket_clock": {"wall_time_ms": 1, "monotonic_ms": 2}}, "clock_invalid")          # no boot identity
    refused(env, {**base, "ticket_clock": {**CLOCK, "wall_time_ms": 1.5}}, "clock_invalid")
    refused(env, {**base, "ticket_clock": {**CLOCK, "monotonic_ms": -1}}, "clock_invalid")
    # Key rotated since the ticket was signed.
    env.monkeypatch.setenv("SHIELD_TICKET_SIGNING_KEY_PEM", pem())
    refused(env, base, "ticket_key_unknown")


def test_an_expired_ticket_is_refused(env):
    phone = Phone()
    old = tickets.issue(env.alice_id, "job-1", now=lambda: 1_000)
    body = {"ticket": old["ticket"], "server_signature_der_b64": old["server_signature_der_b64"], "ticket_clock": CLOCK,
            "signature_der_b64": sign(phone.key, tickets.genesis_client_data(old["ticket_hash"], CLOCK)), "public_key_uncompressed_b64": phone.public_b64}
    refused(env, body, "ticket_expired")


def test_one_start_per_ticket_id_and_an_exact_replay_is_harmless(env):
    phone = Phone()
    h, first, body = start(env, phone, ticket_id="job-1")
    again = env.client.post("/shield/tickets/countersign", json=body, headers=env.alice)
    assert again.status_code == 200 and again.json() == {"ticket_hash": h, "started": True, "already": True}
    _, second, _ = start(env, phone, ticket_id="job-1")  # a fresh ticket for the same id, later
    assert second.status_code == 409 and second.json()["detail"] == "ticket_already_started"
    _, other, _ = start(env, phone, ticket_id="job-2")
    assert other.status_code == 200


def test_the_ticket_routes_need_a_signed_in_account(env):
    assert env.client.post("/shield/tickets", json={"ticket_id": "job-1"}).status_code in (401, 403)
    assert env.client.post("/shield/tickets/countersign", json={}).status_code in (401, 403, 422)
