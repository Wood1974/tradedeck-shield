"""RFC 3161 outside time-stamps: the reply checks (against a reply made by OpenSSL), and the daily run that takes them."""
import base64
import datetime
import json
from pathlib import Path

import pytest
from asn1crypto import tsp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app import captures, outside_time, rfc3161, security
from app.local_identity import LocalIdentity
from app.main import app
from test_captures import PW

V = Path(__file__).parent / "vectors" / "tsa"
REQ = tsp.TimeStampReq.load((V / "req.tsq").read_bytes())
IMPRINT = REQ["message_imprint"]["hashed_message"].native
NONCE = REQ["nonce"].native
REPLY = (V / "resp.tsr").read_bytes()
ROOTS = rfc3161.load_roots((V / "ca.pem").read_bytes())
HEAD = "a" * 64  # the fixture was made for the chain head "aaaa...": chain_head_imprint(HEAD) == IMPRINT


def check(reply=REPLY, imprint=IMPRINT, nonce=NONCE, roots=None):
    return rfc3161.check_reply(reply, imprint, nonce, roots)


def test_the_fixture_is_for_this_head():
    assert rfc3161.chain_head_imprint(HEAD) == IMPRINT


def test_a_real_reply_passes_and_says_whether_the_chain_was_checked():
    out = check()
    assert out["gen_time"].year == 2026 and out["chain_checked"] is False
    assert check(roots=ROOTS)["chain_checked"] is True


def test_a_reply_for_another_hash_or_nonce_is_refused():
    with pytest.raises(rfc3161.TimestampInvalid, match="imprint_mismatch"):
        check(imprint=bytes(32))
    with pytest.raises(rfc3161.TimestampInvalid, match="nonce_mismatch"):
        check(nonce=NONCE + 1)


def test_a_changed_signature_or_changed_time_is_refused():
    resp = tsp.TimeStampResp.load(REPLY)
    sig = resp["time_stamp_token"]["content"]["signer_infos"][0]["signature"].native
    flipped = bytes([sig[0] ^ 1]) + sig[1:]
    with pytest.raises(rfc3161.TimestampInvalid, match="signature_invalid"):
        check(reply=REPLY.replace(sig, flipped))
    gen = b"20261021171642Z"
    assert gen in REPLY
    with pytest.raises(rfc3161.TimestampInvalid, match="message_digest_mismatch"):
        check(reply=REPLY.replace(gen, b"20261021171643Z"))


def test_a_signer_that_does_not_chain_to_the_trusted_root_is_refused():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some Other Root")])
    now = datetime.datetime.now(datetime.timezone.utc)
    root = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(other.public_key()).serial_number(1) \
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30)).sign(other, hashes.SHA256())
    with pytest.raises(rfc3161.TimestampInvalid, match="chain_not_trusted"):
        check(roots=[root])


def test_a_refusal_or_garbage_is_not_kept():
    refused = bytes.fromhex("3005300302010 2".replace(" ", ""))  # TimeStampResp { PKIStatusInfo { status 2 = rejection } }
    with pytest.raises(rfc3161.TimestampInvalid, match="not_granted"):
        check(reply=refused)
    for junk in (b"", b"not der", REPLY[:40], b"\x30\x03\x02\x01\x00"):
        with pytest.raises(rfc3161.TimestampInvalid):
            check(reply=junk)


def test_the_request_carries_only_a_hash_a_nonce_and_a_flag():
    req = tsp.TimeStampReq.load(rfc3161.build_request(IMPRINT, 42))
    assert req["message_imprint"]["hashed_message"].native == IMPRINT
    assert req["nonce"].native == 42 and req["cert_req"].native is True
    assert req["req_policy"].native is None and req["extensions"].native is None
    with pytest.raises(ValueError):
        rfc3161.build_request(b"short", 1)


# --- the daily run and what the API says -------------------------------------------------------------------------------

@pytest.fixture
def env(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", path)
    monkeypatch.setenv("SHIELD_STORAGE_ROOT", str(tmp_path / "storage"))
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    monkeypatch.setattr(rfc3161, "new_nonce", lambda: NONCE)  # the fixture reply is bound to this nonce
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
    e.local, e.client = local, client
    e.alice, e.alice_id = account("alice@example.com")
    e.bob, e.bob_id = account("bob@example.com")
    captures._init(local)

    def put(account_id, record_hash, prev_hash, t=1.0):
        with local.db() as db:
            db.execute("INSERT INTO captures(id,account_id,record_hash,prev_hash,ticket_id,checkpoint_id,photo_sha256,photo_bytes,record_json,"
                       "signature_der_b64,public_key_b64,attest_key_id,attest_status,attest_trusted,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (record_hash[:36], account_id, record_hash, prev_hash, "t", "c", "d" * 64, 1, "{}", "s", "k", None, "none", 0, t))

    e.put = put
    return e


def good_post(url, request):
    assert tsp.TimeStampReq.load(request)["message_imprint"]["hashed_message"].native == IMPRINT
    return REPLY


def test_only_chain_heads_without_a_stamp_are_pending(env):
    env.put(env.alice_id, "1" * 64, "0" * 64)
    env.put(env.alice_id, "2" * 64, "1" * 64)
    env.put(env.bob_id, "3" * 64, "0" * 64)
    assert sorted(outside_time.pending_heads(env.local)) == sorted([(env.alice_id, "2" * 64), (env.bob_id, "3" * 64)])


def test_a_pass_stamps_the_head_once_and_the_records_before_it_are_covered(env):
    env.put(env.alice_id, "b" * 64, "0" * 64)
    env.put(env.alice_id, "c" * 64, "b" * 64)
    env.put(env.alice_id, HEAD, "c" * 64)
    env.put(env.alice_id, "e" * 64, "f" * 64)  # a different chain with no stamp yet
    sent = []
    result = outside_time.stamp_pending(env.local, post=lambda u, r: (sent.append(r), good_post(u, r))[1], roots=[], url="http://tsa.test")
    assert result == {"stamped": 1, "failed": 1}  # the other head's reply is for a different hash and is refused
    assert outside_time.pending_heads(env.local) == [(env.alice_id, "e" * 64)]
    listed = {c["record_hash"]: c["outside_time"] for c in env.client.get("/shield/captures", headers=env.alice).json()["captures"]}
    for covered in ("b" * 64, "c" * 64, HEAD):
        assert listed[covered]["status"] == "stamped" and listed[covered]["tsa"] == "http://tsa.test" and listed[covered]["chain_checked"] is False
    assert listed["e" * 64]["status"] == "off"  # not enabled in this test
    assert all(b"alice" not in r and b"shield.db" not in r for r in sent)


def test_a_failed_call_stores_nothing_and_is_tried_again(env):
    env.put(env.alice_id, HEAD, "0" * 64)

    def down(url, request):
        raise RuntimeError("tsa_http_503")

    assert outside_time.stamp_pending(env.local, post=down, roots=[]) == {"stamped": 0, "failed": 1}
    assert outside_time.pending_heads(env.local) == [(env.alice_id, HEAD)]
    assert outside_time.stamp_pending(env.local, post=good_post, roots=[]) == {"stamped": 1, "failed": 0}
    assert outside_time.stamp_pending(env.local, post=good_post, roots=[]) == {"stamped": 0, "failed": 0}


def test_a_reply_that_fails_its_checks_is_not_kept(env):
    env.put(env.alice_id, HEAD, "0" * 64)
    assert outside_time.stamp_pending(env.local, post=lambda u, r: REPLY.replace(b"20261021171642Z", b"20261021171643Z"), roots=[]) == {"stamped": 0, "failed": 1}
    assert outside_time.stamp_pending(env.local, post=lambda u, r: b"garbage", roots=[]) == {"stamped": 0, "failed": 1}


def test_a_run_happens_at_most_once_a_day_and_the_time_survives_a_restart(env):
    env.put(env.alice_id, HEAD, "0" * 64)
    clock = [1_000_000.0]
    assert outside_time.run_if_due(env.local, post=good_post, roots=[], now=lambda: clock[0]) == {"stamped": 1, "failed": 0}
    env.put(env.alice_id, "9" * 64, HEAD)
    clock[0] += 3600
    assert outside_time.run_if_due(env.local, post=good_post, roots=[], now=lambda: clock[0]) is None
    restarted = LocalIdentity(f"sqlite:///{env.local.path}")
    clock[0] += 86_400
    assert outside_time.run_if_due(restarted, post=lambda u, r: b"x", roots=[], now=lambda: clock[0]) == {"stamped": 0, "failed": 1}


def test_a_record_after_the_last_stamp_waits_when_enabled(env, monkeypatch):
    monkeypatch.setenv("SHIELD_TSA_ENABLED", "true")
    env.put(env.alice_id, HEAD, "0" * 64)
    env.put(env.alice_id, "9" * 64, HEAD)
    outside_time.stamp_pending(env.local, post=good_post, roots=[])  # the head is now "9999..."; the fixture reply is for HEAD, so it is refused
    listed = {c["record_hash"]: c["outside_time"]["status"] for c in env.client.get("/shield/captures", headers=env.alice).json()["captures"]}
    assert listed == {HEAD: "waiting", "9" * 64: "waiting"}


def test_the_stored_reply_is_available_to_its_owner_only_and_checks_out_again(env):
    env.put(env.alice_id, "b" * 64, "0" * 64)
    env.put(env.alice_id, HEAD, "b" * 64)
    outside_time.stamp_pending(env.local, post=good_post, roots=ROOTS)
    got = env.client.get(f"/shield/captures/{'b' * 64}/timestamp", headers=env.alice)
    assert got.status_code == 200
    body = got.json()
    assert body["head_record_hash"] == HEAD and body["chain_checked"] is True
    assert rfc3161.check_reply(base64.b64decode(body["reply_der_b64"]), bytes.fromhex(body["imprint_sha256"]), NONCE, ROOTS)["chain_checked"]
    assert env.client.get(f"/shield/captures/{'b' * 64}/timestamp", headers=env.bob).status_code == 404
    assert env.client.get(f"/shield/captures/{'7' * 64}/timestamp", headers=env.alice).status_code == 404
    assert env.client.get("/shield/captures/not-a-hash/timestamp", headers=env.alice).status_code == 404
    assert env.client.get(f"/shield/captures/{'b' * 64}/timestamp").status_code in (401, 403)


def test_the_daily_job_is_off_unless_enabled(monkeypatch):
    monkeypatch.delenv("SHIELD_TSA_ENABLED", raising=False)
    assert outside_time.enabled() is False
    monkeypatch.setenv("SHIELD_TSA_ENABLED", "true")
    assert outside_time.enabled() is True
