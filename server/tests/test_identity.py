"""ID check + signed note on the standalone Shield server: core rules and routes, with Stripe faked."""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app import identity_api
from app import identity_core as core
from app.local_identity import LocalIdentity


# ---------------------------------------------------------------- helpers --
class Device:
    """Signs like WebCrypto ECDSA P-256: raw 64-byte r||s over canonical JSON."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.raw = self.key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self.pub_b64 = base64.b64encode(self.raw).decode()
        self.seal = core.seal_id_for_key(self.raw)

    def note(self, session_id, signed_at=None, **over):
        payload = {
            "kind": core.NOTE_KIND, "v": 1, "statement": core.STATEMENT, "statementVersion": core.STATEMENT_VERSION,
            "sessionId": session_id, "deviceSealId": self.seal,
            "signedAt": (signed_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
        }
        payload.update(over)
        r, s = utils.decode_dss_signature(self.key.sign(core.canonical(payload).encode(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {"payload": payload, "devicePublicKey": self.pub_b64, "signature": base64.b64encode(sig).decode()}


class FakeStripe:
    """Stands in for stripe.identity.VerificationSession."""

    def __init__(self):
        self.status, self.created, self.keys = "requires_input", 0, []

    def create(self, api_key=None, **kw):
        self.keys.append(api_key)
        self.created += 1
        assert kw["type"] == "document"
        assert kw["options"]["document"] == {"require_matching_selfie": True, "require_live_capture": True}
        return SimpleNamespace(id=f"vs_{self.created}", status="requires_input", url=f"https://verify.stripe.com/s/vs_{self.created}")

    def retrieve(self, sid, api_key=None):
        self.keys.append(api_key)
        return SimpleNamespace(id=sid, status=self.status)


def _pem(key):
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


@pytest.fixture
def env(monkeypatch, tmp_path):
    from app.main import app
    receipt_key = ec.generate_private_key(ec.SECP256R1())
    db_url = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", db_url)
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("SHIELD_RATE_LIMIT_PER_MINUTE", "100000")
    monkeypatch.setenv("IDENTITY_RECEIPT_KEY", _pem(receipt_key))
    for var in ("STRIPE_TEST_SECRET_KEY", "IDENTITY_TEST_MODE_EMAILS"):
        monkeypatch.delenv(var, raising=False)
    local = LocalIdentity(db_url)
    local.create_account("owner@example.com", "owner-password-123", "admin")
    local.create_account("worker@example.com", "worker-password-123", "capturer")
    st = FakeStripe()
    monkeypatch.setattr(identity_api.stripe.identity, "VerificationSession", st)
    client = TestClient(app)
    # The per-IP rate limiter is process-wide: start these tests with it empty and leave it empty for the next file.
    from app import security
    security._BUCKETS.clear()

    def login(email, password):
        r = client.post("/shield/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    return SimpleNamespace(client=client, stripe=st, receipt_key=receipt_key, monkeypatch=monkeypatch, db_url=db_url,
                           owner=login("owner@example.com", "owner-password-123"),
                           worker=login("worker@example.com", "worker-password-123"), login=login)


CONSENT = {"consent": True, "consentVersion": identity_api.CONSENT_VERSION}


def rows(env, table):
    import sqlite3
    con = sqlite3.connect(env.db_url.removeprefix("sqlite:///"))
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(f"SELECT * FROM {table}")]
    finally:
        con.close()


def start_and_verify(env, headers=None):
    headers = headers or env.worker
    sid = env.client.post("/identity/start", json=CONSENT, headers=headers).json()["sessionId"]
    env.stripe.status = "verified"
    return sid


# ------------------------------------------------------------------- core --
def test_statement_is_pinned():
    # Same digest is pinned in shield-app/src/identity/note.test.ts. Change both together, with a new version.
    assert core.statement_sha256() == "8bde7dfaa7949d57d0179ecb7f6a8a6dfc0ecd11912604d22ca528589074945c"


def test_canonical_matches_the_phone():
    assert core.canonical({"b": 1, "a": [2, {"d": 1, "c": "é"}]}) == '{"a":[2,{"c":"é","d":1}],"b":1}'


def test_valid_note_verifies():
    d = Device()
    ok, why, sha = core.verify_note(d.note("vs_1"), "vs_1")
    assert (ok, why) == (True, "ok") and len(sha) == 64


@pytest.mark.parametrize("over,reason", [
    ({"statement": "I did not take these."}, "statement-mismatch"),
    ({"statementVersion": "2"}, "statement-mismatch"),
    ({"sessionId": "vs_other"}, "session-mismatch"),
    ({"deviceSealId": "00000000·00000000"}, "seal-id-key-mismatch"),
    ({"kind": "something.else"}, "bad-kind"),
])
def test_rejects_wrong_payload(over, reason):
    d = Device()
    assert core.verify_note(d.note("vs_1", **over), "vs_1")[1] == reason


def test_rejects_tampered_payload_and_foreign_key_and_clock():
    d = Device()
    n = d.note("vs_1")
    n["payload"]["signedAt"] = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    assert core.verify_note(n, "vs_1")[1] == "signature-invalid"
    other = Device()
    n2 = d.note("vs_1")
    n2["devicePublicKey"] = other.pub_b64
    assert core.verify_note(n2, "vs_1")[1] == "seal-id-key-mismatch"
    old = d.note("vs_1", signed_at=datetime.now(timezone.utc) - timedelta(hours=1))
    assert core.verify_note(old, "vs_1")[1] == "clock-skew"


def test_rejects_der_and_garbage():
    d = Device()
    n = d.note("vs_1")
    n["signature"] = base64.b64encode(b"\x30" + b"\x00" * 70).decode()
    assert core.verify_note(n, "vs_1")[1] == "bad-signature-format"
    assert core.verify_note({"payload": 5}, "vs_1")[0] is False
    assert core.verify_note({}, "vs_1")[1] == "malformed"


# ----------------------------------------------------------------- routes --
def test_statement_endpoint_is_public(env):
    j = env.client.get("/identity/statement").json()
    assert j["sha256"] == core.statement_sha256() and j["version"] == "1"


def test_requires_auth(env):
    assert env.client.post("/identity/start", json=CONSENT).status_code == 401
    assert env.client.get("/identity/status").status_code == 401
    assert env.client.post("/identity/note", json={}).status_code == 401
    assert env.client.post("/identity/start", json=CONSENT, headers={"Authorization": "Bearer nonsense"}).status_code == 401


def test_a_deactivated_account_loses_access(env):
    other = env.client.post("/shield/admin/accounts", json={"email": "gone@example.com", "password": "gone-password-123"}, headers=env.owner).json()
    h = env.login("gone@example.com", "gone-password-123")
    assert env.client.get("/identity/status", headers=h).status_code == 200
    env.client.post(f"/shield/admin/accounts/{other['account_id']}/deactivate", headers=env.owner)
    assert env.client.get("/identity/status", headers=h).status_code == 401


def test_start_needs_explicit_consent(env):
    assert env.client.post("/identity/start", json={}, headers=env.worker).status_code == 400
    assert env.client.post("/identity/start", json={"consent": "yes", "consentVersion": "1"}, headers=env.worker).status_code == 400
    assert env.client.post("/identity/start", content="not json", headers=env.worker).status_code == 400
    assert env.stripe.created == 0


def test_start_creates_session_and_stores_no_personal_data(env):
    j = env.client.post("/identity/start", json=CONSENT, headers=env.worker).json()
    assert j["status"] == "requires_input" and j["url"].startswith("https://verify.stripe.com/")
    row = rows(env, "identity_sessions")[0]
    assert set(row) == {"id", "account_id", "stripe_session_id", "status", "livemode", "consent_at", "consent_version", "created_at", "updated_at", "verified_at"}
    assert row["livemode"] == 1


def test_status_reads_stripe_not_the_client(env):
    env.client.post("/identity/start", json=CONSENT, headers=env.worker)
    assert env.client.get("/identity/status", headers=env.worker).json()["verified"] is False
    env.stripe.status = "verified"
    assert env.client.get("/identity/status", headers=env.worker).json()["verified"] is True
    assert rows(env, "identity_sessions")[0]["verified_at"]


def test_status_is_none_before_any_check(env):
    assert env.client.get("/identity/status", headers=env.worker).json() == {"status": "none", "verified": False}


def test_note_refused_until_verified(env):
    d = Device()
    sid = env.client.post("/identity/start", json=CONSENT, headers=env.worker).json()["sessionId"]
    r = env.client.post("/identity/note", json=d.note(sid), headers=env.worker)
    assert r.status_code == 409 and r.json()["error"] == "id-check-not-verified"


def test_note_refused_without_any_id_check(env):
    assert env.client.post("/identity/note", json=Device().note("vs_1"), headers=env.worker).status_code == 409


def test_one_account_cannot_use_anothers_id_check(env):
    d = Device()
    sid = start_and_verify(env, env.worker)
    # The owner never started a check, so the worker's verified session is not theirs to sign against.
    assert env.client.post("/identity/note", json=d.note(sid), headers=env.owner).status_code == 409


def test_note_accepted_once_then_idempotent_and_publicly_checkable(env):
    d = Device()
    sid = start_and_verify(env)
    note = d.note(sid)
    r = env.client.post("/identity/note", json=note, headers=env.worker)
    assert r.status_code == 201
    att = r.json()
    again = env.client.post("/identity/note", json=note, headers=env.worker)
    assert again.status_code == 200 and again.json()["attestationId"] == att["attestationId"]
    assert again.json()["receipt"] == att["receipt"]  # the same receipt, not a fresh one
    assert len(rows(env, "note_attestations")) == 1
    pub = env.client.get(f"/identity/attestations/{att['attestationId']}").json()
    assert pub["verified"] is True and pub["noteSha256"] == att["noteSha256"] and pub["deviceSealId"] == d.seal
    assert set(pub) == {"attestationId", "verified", "noteSha256", "deviceSealId", "signedAt", "statementVersion", "provider"}


def test_note_with_bad_signature_is_rejected(env):
    d = Device()
    sid = start_and_verify(env)
    n = d.note(sid)
    n["payload"]["deviceSealId"] = "00000000·00000000"
    assert env.client.post("/identity/note", json=n, headers=env.worker).status_code == 400
    assert not rows(env, "note_attestations")


def test_public_lookup_handles_unknown_and_malformed_ids(env):
    assert env.client.get("/identity/attestations/not-a-uuid").status_code == 404
    assert env.client.get(f"/identity/attestations/{uuid.uuid4()}").status_code == 404


# ---------------------------------------------------------------- receipt --
# Cross-language vector: the same receipt, key and signature are verified by the phone in
# shield-app/src/identity/receipt.test.ts. The key is a throwaway made for this test, not a real key.
VECTOR_PUB = "BK9KLQI7FrDwxKlg4FEpLz4MkVcEs8n9yqAslQzczPf9Aed0/GocEwPX1VNbDZQTQkMWag/j+n7UNTFt196/6pM="
VECTOR = {
    "payload": {
        "kind": "tradedeck.shield.idreceipt", "v": 1, "attestationId": "66666666-6666-4666-8666-666666666666",
        "noteSha256": "b" * 64, "deviceSealId": "AAAAAAAA\u00b7BBBBBBBB",
        "sessionSha256": "9d4c448fe82e0f2a7f32726170adde6932087bf87fa5f693b7b6dd5f99cff474",
        "idCheck": {"provider": "stripe-identity", "status": "verified"},
        "issuedAt": "2026-10-11T12:00:00Z", "kid": "1a473f66e378a662",
    },
    "signature": "uzbbuUQjxU6wvVHMGAXsviysDU+m1lGF8wRqGITK8Ltq17pl6z4YIzY+U6WFskTq9z5NWoWguuGas8Kt/zKxJw==",
}


def test_vector_verifies_and_rejects_edits():
    assert core.verify_receipt(VECTOR, VECTOR_PUB) == (True, "ok")
    edited = json.loads(json.dumps(VECTOR))
    edited["payload"]["noteSha256"] = "c" * 64
    assert core.verify_receipt(edited, VECTOR_PUB) == (False, "signature-invalid")
    edited = json.loads(json.dumps(VECTOR))
    edited["payload"]["idCheck"]["status"] = "requires_input"
    assert core.verify_receipt(edited, VECTOR_PUB)[0] is False
    assert core.verify_receipt(VECTOR, base64.b64encode(Device().raw).decode())[1] == "kid-mismatch"


def test_note_response_carries_a_receipt_that_verifies_with_the_published_key(env):
    d = Device()
    sid = start_and_verify(env)
    att = env.client.post("/identity/note", json=d.note(sid), headers=env.worker).json()
    key = env.client.get("/identity/receipt-key").json()
    assert core.verify_receipt(att["receipt"], key["publicKey"]) == (True, "ok")
    p = att["receipt"]["payload"]
    assert (p["attestationId"], p["noteSha256"], p["deviceSealId"]) == (att["attestationId"], att["noteSha256"], d.seal)
    assert p["kid"] == key["kid"] and p["sessionSha256"] == core.sha256_hex(sid.encode())
    assert sid not in json.dumps(att["receipt"])  # the Stripe session id itself is not published


def test_receipt_is_bound_to_this_note_and_not_reusable(env):
    sid = start_and_verify(env)
    a = env.client.post("/identity/note", json=Device().note(sid), headers=env.worker).json()
    b = env.client.post("/identity/note", json=Device().note(sid), headers=env.worker).json()
    assert a["receipt"]["payload"]["noteSha256"] != b["receipt"]["payload"]["noteSha256"]
    swapped = {"payload": {**a["receipt"]["payload"], "noteSha256": b["noteSha256"]}, "signature": a["receipt"]["signature"]}
    key = env.client.get("/identity/receipt-key").json()["publicKey"]
    assert core.verify_receipt(swapped, key)[0] is False


def test_no_note_is_accepted_without_a_receipt_key(env):
    d = Device()
    sid = start_and_verify(env)
    env.monkeypatch.delenv("IDENTITY_RECEIPT_KEY")
    r = env.client.post("/identity/note", json=d.note(sid), headers=env.worker)
    assert r.status_code == 503 and r.json()["error"] == "receipt-key-not-configured"
    assert not rows(env, "note_attestations")
    assert env.client.get("/identity/receipt-key").status_code == 503


def test_a_non_p256_receipt_key_is_refused_not_used(env):
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    env.monkeypatch.setenv("IDENTITY_RECEIPT_KEY", _pem(_ec.generate_private_key(_ec.SECP384R1())))
    d = Device()
    sid = start_and_verify(env)
    assert env.client.post("/identity/note", json=d.note(sid), headers=env.worker).status_code == 503


# -------------------------------------------------------------- rate limit --
def test_start_is_limited_per_account_per_day(env):
    for _ in range(identity_api.MAX_ID_CHECKS_PER_DAY):
        assert env.client.post("/identity/start", json=CONSENT, headers=env.worker).status_code == 200
    assert env.stripe.created == identity_api.MAX_ID_CHECKS_PER_DAY
    r = env.client.post("/identity/start", json=CONSENT, headers=env.worker)
    assert r.status_code == 429 and r.json()["error"] == "too-many-id-checks"
    assert env.stripe.created == identity_api.MAX_ID_CHECKS_PER_DAY  # the refused call never reached Stripe
    assert env.client.post("/identity/start", json=CONSENT, headers=env.owner).status_code == 200  # another account is unaffected


def test_old_sessions_do_not_count_toward_the_limit(env):
    import sqlite3
    env.client.post("/identity/start", json=CONSENT, headers=env.worker)
    con = sqlite3.connect(env.db_url.removeprefix("sqlite:///"))
    con.execute("UPDATE identity_sessions SET created_at = created_at - 172800")
    con.commit(); con.close()
    for _ in range(identity_api.MAX_ID_CHECKS_PER_DAY):
        assert env.client.post("/identity/start", json=CONSENT, headers=env.worker).status_code == 200


# ------------------------------------------------------------- test mode --
TEST_KEY = "sk_test_abc123"


def _owner(env, key=TEST_KEY, allow="owner@example.com"):
    env.monkeypatch.setenv("STRIPE_TEST_SECRET_KEY", key)
    env.monkeypatch.setenv("IDENTITY_TEST_MODE_EMAILS", allow)


def test_live_is_the_default_and_uses_no_special_key(env):
    env.client.post("/identity/start", json=CONSENT, headers=env.owner)
    assert env.stripe.keys == [None]
    assert rows(env, "identity_sessions")[0]["livemode"] == 1


def test_an_allowlisted_account_runs_in_test_mode_with_the_test_key(env):
    _owner(env)
    env.client.post("/identity/start", json=CONSENT, headers=env.owner)
    assert env.stripe.keys == [TEST_KEY]
    assert rows(env, "identity_sessions")[0]["livemode"] == 0
    env.client.get("/identity/status", headers=env.owner)
    assert env.stripe.keys == [TEST_KEY, TEST_KEY]  # status asks Stripe with the matching key


def test_the_allowlist_ignores_email_case_and_spaces(env):
    _owner(env, allow=" Other@example.com , OWNER@Example.com ")
    env.client.post("/identity/start", json=CONSENT, headers=env.owner)
    assert env.stripe.keys == [TEST_KEY]


def test_other_accounts_stay_live_even_when_test_mode_is_configured(env):
    _owner(env)
    env.client.post("/identity/start", json=CONSENT, headers=env.worker)
    assert env.stripe.keys == [None]
    assert rows(env, "identity_sessions")[0]["livemode"] == 1


@pytest.mark.parametrize("key", ["sk_live_abc123", "", "whsec_nope"])
def test_a_key_that_is_not_a_test_key_is_never_used_for_test_mode(env, key):
    _owner(env, key=key)
    env.client.post("/identity/start", json=CONSENT, headers=env.owner)
    assert env.stripe.keys == [None]  # the allowlisted owner falls back to a live check, never to a live key as "test"


def test_an_empty_allowlist_means_nobody_gets_test_mode(env):
    _owner(env, allow=" , ")
    env.client.post("/identity/start", json=CONSENT, headers=env.owner)
    assert env.stripe.keys == [None]


def test_a_test_session_is_refused_if_test_mode_is_switched_off(env):
    _owner(env)
    env.client.post("/identity/start", json=CONSENT, headers=env.owner)
    env.monkeypatch.delenv("STRIPE_TEST_SECRET_KEY")
    r = env.client.get("/identity/status", headers=env.owner)
    assert r.status_code == 502 and r.json()["error"] == "id-check-unavailable"


def test_a_test_receipt_is_signed_and_marked_and_a_live_receipt_is_not(env):
    _owner(env)
    sid = start_and_verify(env, env.owner)
    att = env.client.post("/identity/note", json=Device().note(sid), headers=env.owner).json()
    key = env.client.get("/identity/receipt-key").json()["publicKey"]
    assert core.verify_receipt(att["receipt"], key) == (True, "ok")
    assert att["receipt"]["payload"]["testMode"] is True
    # The mark is inside the signature: removing it breaks the receipt.
    stripped = {"payload": {k: v for k, v in att["receipt"]["payload"].items() if k != "testMode"}, "signature": att["receipt"]["signature"]}
    assert core.verify_receipt(stripped, key)[0] is False
    # A live receipt carries no such field at all, so live receipts are unchanged.
    live = core.make_receipt(env.receipt_key, attestation_id="a", note_sha256="b" * 64, device_seal_id="X", session_id="vs_1")
    assert "testMode" not in live["payload"]


def test_a_test_check_never_reads_as_verified_to_a_third_party(env):
    _owner(env)
    sid = start_and_verify(env, env.owner)
    att = env.client.post("/identity/note", json=Device().note(sid), headers=env.owner).json()
    pub = env.client.get(f"/identity/attestations/{att['attestationId']}").json()
    assert pub["verified"] is False and pub["testMode"] is True


# ------------------------------------------------------------------- cors --
@pytest.mark.parametrize("origin", ["capacitor://localhost", "https://localhost"])
def test_the_phone_apps_own_origin_passes_the_preflight(env, origin):
    r = env.client.options("/identity/start", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == origin
    assert "authorization" in r.headers["access-control-allow-headers"].lower()


def test_an_unknown_origin_gets_no_cors_headers(env):
    r = env.client.options("/identity/start", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers


# ------------------------------------------------------- first administrator --
def test_the_first_admin_is_created_from_the_bootstrap_variables_once(monkeypatch, tmp_path):
    from app.local_identity import ensure_bootstrap_admin
    monkeypatch.setenv("SHIELD_DATABASE_URL", f"sqlite:///{tmp_path / 'shield.db'}")
    monkeypatch.delenv("SHIELD_BOOTSTRAP_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("SHIELD_BOOTSTRAP_ADMIN_PASSWORD", raising=False)
    assert ensure_bootstrap_admin() is False  # nothing configured, nothing created
    monkeypatch.setenv("SHIELD_BOOTSTRAP_ADMIN_EMAIL", "First@Example.com")
    monkeypatch.setenv("SHIELD_BOOTSTRAP_ADMIN_PASSWORD", "first-password-123")
    assert ensure_bootstrap_admin() is True
    acct = LocalIdentity(f"sqlite:///{tmp_path / 'shield.db'}").authenticate("first@example.com", "first-password-123")
    assert acct is not None and acct.role == "admin"
    monkeypatch.setenv("SHIELD_BOOTSTRAP_ADMIN_EMAIL", "second@example.com")
    assert ensure_bootstrap_admin() is False  # an admin exists, so the variables can never add another
    assert LocalIdentity(f"sqlite:///{tmp_path / 'shield.db'}").authenticate("second@example.com", "first-password-123") is None


def test_a_too_short_bootstrap_password_creates_nothing(monkeypatch, tmp_path):
    from app.local_identity import ensure_bootstrap_admin
    monkeypatch.setenv("SHIELD_DATABASE_URL", f"sqlite:///{tmp_path / 'shield.db'}")
    monkeypatch.setenv("SHIELD_BOOTSTRAP_ADMIN_EMAIL", "first@example.com")
    monkeypatch.setenv("SHIELD_BOOTSTRAP_ADMIN_PASSWORD", "short")
    with pytest.raises(ValueError):
        ensure_bootstrap_admin()
    assert LocalIdentity(f"sqlite:///{tmp_path / 'shield.db'}").authenticate("first@example.com", "short") is None
