"""Apple's evidence is kept and can be re-checked without the server.

Through the real routes: a phone enrols (synthetic Apple-style chain, as in test_attest_chain.py), uploads a photo with an assertion,
and the account fetches the evidence. verifier/shield_apple_verify.py then checks it with only that JSON and the root certificate.
Apple's real chain has never been run through this code; the first real iPhone is that test."""
import base64
import copy
import hashlib
import importlib.util
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509

import app.attestation as attestation
from app import main
from app.attestation import APPLE_NONCE_OID, PROD_AAGUID, AttestationVerifier
from app.store import Store
from test_attest_chain import APP_ID, Chain, _cert
from test_attestation import make_assertion
from test_captures import env, photo  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("shield_apple_verify", ROOT / "verifier" / "shield_apple_verify.py")
av = importlib.util.module_from_spec(spec)
spec.loader.exec_module(av)

b64 = lambda raw: base64.b64encode(raw).decode("ascii")


class Enrolled:
    """A phone that enrolled through the routes; keeps the attested private key so it can sign assertions."""


@pytest.fixture
def apple(env, tmp_path, monkeypatch):
    chain = Chain()
    pem = tmp_path / "root.pem"
    pem.write_bytes(chain.root.public_bytes(Encoding.PEM))
    monkeypatch.setattr(attestation, "APPLE_ROOT_PEM", pem)
    store = Store(f"sqlite:///{tmp_path / 'store.db'}", str(tmp_path / "evidence"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "att", AttestationVerifier("production", APP_ID, store=store))

    def enrol(headers):
        challenge = env.client.post("/shield/attest/challenge", headers=headers).json()["nonce"]
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        raw = leaf_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        cred = hashlib.sha256(raw).digest()
        cose = {1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]}
        auth = (hashlib.sha256(APP_ID.encode()).digest() + b"\x41" + struct.pack(">I", 0) + PROD_AAGUID
                + struct.pack(">H", len(cred)) + cred + cbor2.dumps(cose))
        nonce = hashlib.sha256(auth + hashlib.sha256(challenge.encode()).digest()).digest()
        ext = x509.UnrecognizedExtension(APPLE_NONCE_OID, bytes([0x30, 0x24, 0xA1, 0x22, 0x04, 0x20]) + nonce)
        leaf = _cert("leaf", "Apple App Attestation CA 1", leaf_key, chain.inter_key, ca=False, extra=ext)
        blob = cbor2.dumps({"fmt": "apple-appattest", "attStmt": {"x5c": [leaf.public_bytes(Encoding.DER), chain.inter.public_bytes(Encoding.DER)], "receipt": b"r"}, "authData": auth})
        r = env.client.post("/shield/attest", data={"key_id": b64(cred), "nonce": challenge, "attestation": b64(blob)}, headers=headers)
        assert r.status_code == 200, r.text
        e = Enrolled()
        e.key, e.key_id, e.counter = leaf_key, b64(cred), 0
        return e

    a = Enrolled()
    a.chain, a.store, a.root_pem, a.enrol = chain, store, chain.root.public_bytes(Encoding.PEM), enrol
    return a


def send_photo(env, phone_key, with_assertion=True, counter=1, n=1):
    upload = env.phone.seal(photo(n))
    if with_assertion:
        upload["app_attest_key_id"] = phone_key.key_id
        upload["app_attest_assertion_b64"] = make_assertion(phone_key.key, APP_ID, bytes.fromhex(upload["record"]["record_hash"]), counter)
    r = env.upload(upload)
    assert r.status_code == 200, r.text
    return upload["record"]["record_hash"], r.json()


def evidence(env, record_hash, headers=None):
    return env.client.get(f"/shield/captures/{record_hash}/evidence", headers=env.alice if headers is None else headers)


def test_enrolment_keeps_the_attestation_and_a_photo_keeps_its_assertion(env, apple):
    key = apple.enrol(env.alice)
    record_hash, body = send_photo(env, key)
    assert body["attest"] == {"status": "verified", "trusted": True}
    got = evidence(env, record_hash).json()
    assert got["record_hash"] == record_hash and got["record"]["record_hash"] == record_hash
    assert got["apple"]["kept"] is True and got["apple"]["key_id"] == key.key_id and got["apple"]["app_id"] == APP_ID
    assert got["apple"]["attestation_b64"] and got["apple"]["assertion_b64"] and got["apple"]["challenge"]


def test_the_offline_checker_passes_what_the_server_kept_and_says_what_it_did_not_check(env, apple):
    record_hash, _ = send_photo(env, apple.enrol(env.alice))
    code, lines = av.check(evidence(env, record_hash).json(), apple.root_pem)
    assert code == 0, lines
    tags = {tag for tag, _ in lines}
    assert tags == {"CHECKED", "NOT CHECKED"}
    not_checked = " ".join(text for tag, text in lines if tag == "NOT CHECKED")
    assert "validity" in not_checked and "counter" in not_checked  # never reported as a pass


def test_validity_is_judged_at_the_time_you_give(env, apple):
    record_hash, _ = send_photo(env, apple.enrol(env.alice))
    ev = evidence(env, record_hash).json()
    now = datetime.now(timezone.utc)
    assert av.check(ev, apple.root_pem, now)[0] == 0
    code, lines = av.check(ev, apple.root_pem, now + timedelta(days=30))
    assert code == 2 and lines[-1][0] == "FAILED"


@pytest.mark.parametrize("tamper", ["record_hash", "challenge", "app_id", "key_id", "assertion", "attestation"])
def test_every_kind_of_tampering_fails_offline(env, apple, tamper):
    record_hash, _ = send_photo(env, apple.enrol(env.alice))
    ev = copy.deepcopy(evidence(env, record_hash).json())
    if tamper == "record_hash":  # the assertion was over another photo
        other = "b" * 64
        ev["record_hash"], ev["record"]["record_hash"] = other, other
    elif tamper == "challenge":
        ev["apple"]["challenge"] += "x"
    elif tamper == "app_id":
        ev["apple"]["app_id"] = "OTHERTEAM.app.other"
    elif tamper == "key_id":
        ev["apple"]["key_id"] = b64(hashlib.sha256(b"another key").digest())
    elif tamper == "assertion":
        raw = bytearray(base64.b64decode(ev["apple"]["assertion_b64"]))
        raw[-1] ^= 1
        ev["apple"]["assertion_b64"] = b64(bytes(raw))
    else:
        raw = bytearray(base64.b64decode(ev["apple"]["attestation_b64"]))
        raw[len(raw) // 2] ^= 1
        ev["apple"]["attestation_b64"] = b64(bytes(raw))
    code, lines = av.check(ev, apple.root_pem)
    assert code == 2 and any(tag == "FAILED" for tag, _ in lines), lines


def test_a_different_root_fails(env, apple):
    record_hash, _ = send_photo(env, apple.enrol(env.alice))
    other = Chain().root.public_bytes(Encoding.PEM)
    assert av.check(evidence(env, record_hash).json(), other)[0] == 2


def test_the_command_line_exit_codes(env, apple, tmp_path):
    record_hash, _ = send_photo(env, apple.enrol(env.alice))
    path, root = tmp_path / "ev.json", tmp_path / "root.pem"
    import json
    path.write_text(json.dumps(evidence(env, record_hash).json()))
    root.write_bytes(apple.root_pem)
    assert av.main([str(path), "--root", str(root)]) == 0


def test_a_photo_sent_without_an_assertion_says_so_and_is_not_a_pass(env, apple):
    key = apple.enrol(env.alice)
    record_hash, _ = send_photo(env, key, with_assertion=False)
    got = evidence(env, record_hash).json()
    assert got["apple"]["kept"] is False and "no phone key" in got["apple"]["reason"]
    code, lines = av.check(got, apple.root_pem)
    assert code == 3 and lines[0][0] == "NOT PRESENT"


def test_a_key_enrolled_before_evidence_was_kept_says_so(env, apple):
    me = env.client.get("/shield/auth/me", headers=env.alice).json()
    account_id = me.get("account_id") or me.get("id")
    key = Enrolled()
    key.key, key.key_id = ec.generate_private_key(ec.SECP256R1()), "old-key"
    apple.store.save_attestation_key("old-key", account_id, b64(key.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)), "production", "")
    record_hash, _ = send_photo(env, key)
    got = evidence(env, record_hash).json()
    assert got["apple"]["kept"] is False and "enrolled before" in got["apple"]["reason"]
    assert av.check(got, apple.root_pem)[0] == 3


def test_only_the_owner_can_fetch_evidence_and_bad_hashes_are_404(env, apple):
    record_hash, _ = send_photo(env, apple.enrol(env.alice))
    bob = env.account("bob@example.com")
    assert evidence(env, record_hash, bob).status_code == 404
    assert env.client.get(f"/shield/captures/{record_hash}/evidence").status_code in (401, 403)
    assert evidence(env, "z" * 64).status_code == 404
    assert evidence(env, "a" * 64).status_code == 404
