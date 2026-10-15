"""verify_attestation against a synthetic Apple-style chain.

The real Apple root is swapped for a throwaway root made here, so every check the server runs on a registration
(chain, nonce, key id, app id hash, counter, AAGUID) is exercised. Apple's real chain has never been run through
this code; the first real device is that test.
"""
import base64
import datetime
import hashlib
import struct

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

import app.attestation as attestation
from app.attestation import APPLE_NONCE_OID, DEV_AAGUID, PROD_AAGUID, AttestationVerifier

APP_ID = "766456AWH4.app.tradedeck.shield"
ROOT_CN = "Apple App Attestation Root CA"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, key, issuer_key, *, ca, extra=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if extra is not None:
        builder = builder.add_extension(extra, critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


class Chain:
    """A fake Apple root + intermediate, and a builder for attestation objects signed under them."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert(ROOT_CN, ROOT_CN, self.root_key, self.root_key, ca=True)
        self.inter = _cert("Apple App Attestation CA 1", ROOT_CN, self.inter_key, self.root_key, ca=True)

    def attest(self, challenge: bytes, *, app_id=APP_ID, aaguid=PROD_AAGUID, counter=0, with_nonce=True, nonce_for=None):
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        raw = leaf_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        cred_id = hashlib.sha256(raw).digest()
        cose = {1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]}
        auth = (hashlib.sha256(app_id.encode()).digest() + b"\x41" + struct.pack(">I", counter) + aaguid
                + struct.pack(">H", len(cred_id)) + cred_id + cbor2.dumps(cose))
        nonce = hashlib.sha256(auth + hashlib.sha256(nonce_for if nonce_for is not None else challenge).digest()).digest()
        # Apple's extension: SEQUENCE { [1] { OCTET STRING nonce } }
        extra = x509.UnrecognizedExtension(APPLE_NONCE_OID, bytes([0x30, 0x24, 0xA1, 0x22, 0x04, 0x20]) + nonce) if with_nonce else None
        leaf = _cert("leaf", "Apple App Attestation CA 1", leaf_key, self.inter_key, ca=False, extra=extra)
        stmt = {"x5c": [leaf.public_bytes(Encoding.DER), self.inter.public_bytes(Encoding.DER)], "receipt": b"receipt"}
        blob = cbor2.dumps({"fmt": "apple-appattest", "attStmt": stmt, "authData": auth})
        return base64.b64encode(blob).decode(), base64.b64encode(cred_id).decode()


@pytest.fixture
def chain(tmp_path, monkeypatch):
    c = Chain()
    pem = tmp_path / "root.pem"
    pem.write_bytes(c.root.public_bytes(Encoding.PEM))
    monkeypatch.setattr(attestation, "APPLE_ROOT_PEM", pem)
    return c


def test_a_genuine_production_attestation_is_accepted(chain):
    blob, key_id = chain.attest(b"nonce-1")
    result = AttestationVerifier("production", APP_ID).verify_attestation(blob, key_id, b"nonce-1")
    assert result["trusted"] is True and result["status"] == "attested"
    assert result["environment"] == "production" and result["public_key_der_b64"]


def test_a_development_build_attests_only_outside_production(chain):
    blob, key_id = chain.attest(b"n", aaguid=DEV_AAGUID)
    assert AttestationVerifier("production", APP_ID).verify_attestation(blob, key_id, b"n")["status"] == "aaguid_mismatch"
    assert AttestationVerifier("development", APP_ID).verify_attestation(blob, key_id, b"n")["trusted"] is True


def test_the_wrong_app_id_is_refused(chain):
    blob, key_id = chain.attest(b"n")
    result = AttestationVerifier("production", "766457AWH4.com.tradedeck.shield").verify_attestation(blob, key_id, b"n")
    assert result == {"trusted": False, "status": "app_id_hash_mismatch"}


def test_a_proof_for_another_challenge_is_refused(chain):
    blob, key_id = chain.attest(b"challenge-A")
    assert AttestationVerifier("production", APP_ID).verify_attestation(blob, key_id, b"challenge-B")["status"] == "attestation_nonce_mismatch"


def test_a_missing_nonce_extension_is_refused(chain):
    blob, key_id = chain.attest(b"n", with_nonce=False)
    assert AttestationVerifier("production", APP_ID).verify_attestation(blob, key_id, b"n")["status"] == "missing_nonce_extension"


def test_a_key_id_that_is_not_the_attested_key_is_refused(chain):
    blob, _ = chain.attest(b"n")
    other = base64.b64encode(hashlib.sha256(b"someone else").digest()).decode()
    assert AttestationVerifier("production", APP_ID).verify_attestation(blob, other, b"n")["status"] == "key_id_mismatch"


def test_a_nonzero_counter_is_refused(chain):
    blob, key_id = chain.attest(b"n", counter=3)
    assert AttestationVerifier("production", APP_ID).verify_attestation(blob, key_id, b"n")["status"] == "attestation_counter_not_zero"


def test_a_chain_not_signed_by_the_pinned_root_is_refused(chain):
    forged = Chain()  # same names, different keys: only the signature check can tell
    blob, key_id = forged.attest(b"n")
    result = AttestationVerifier("production", APP_ID).verify_attestation(blob, key_id, b"n")
    assert result["trusted"] is False and result["status"]


def test_garbage_is_refused_with_a_reason(chain):
    result = AttestationVerifier("production", APP_ID).verify_attestation("bm90IGNib3I=", "AAAA", b"n")
    assert result["trusted"] is False and result["status"]
