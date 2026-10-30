#!/usr/bin/env python3
"""Check Apple's evidence for a Shield photo without the Shield server.

Input: the JSON a signed-in account gets from GET /shield/captures/<record_hash>/evidence, and Apple's App Attestation root
certificate (published by Apple; pass the file with --root). Nothing here calls Shield or Apple.

  python shield_apple_verify.py evidence.json --root Apple_App_Attestation_Root_CA.pem [--at 2026-10-30T12:00:00Z]

Needs `cryptography` and `cbor2` (pip install cryptography cbor2).

What a pass means: the attestation object chains to Apple's root; it was made over the stated challenge for the stated app id by a
real Apple key whose id matches; and that same key signed an assertion over this photo's record hash. It does not say who held the
phone, that the scene is true, or when the photo was taken. The device signature, hash chain and photo hash are checked by
shield_vault_verify.py, not here.

Each line says CHECKED, FAILED or NOT CHECKED. A pass is "all CHECKED"; NOT CHECKED is never a pass.
Certificate validity windows are only checked when you pass --at (an Apple key certificate is short-lived, so "now" is the wrong
moment to judge it; the right moment is when the key enrolled).

Exit code: 0 all checks passed, 2 a check failed, 3 the evidence was not kept.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
import sys
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

APPLE_NONCE_OID = ObjectIdentifier("1.2.840.113635.100.8.2")
PROD_AAGUID = b"appattest" + b"\x00" * 7
DEV_AAGUID = b"appattestdevelop"


class Failed(Exception):
    pass


def _b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _auth_data(data: bytes, attestation: bool) -> dict:
    if len(data) < 37:
        raise Failed("authenticator data too short")
    out = {"rp_id_hash": data[:32], "counter": struct.unpack(">I", data[33:37])[0]}
    if attestation:
        if len(data) < 55:
            raise Failed("attestation authenticator data too short")
        length = struct.unpack(">H", data[53:55])[0]
        out.update(aaguid=data[37:53], credential_id=data[55:55 + length])
    return out


def _signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise Failed("issuer key is not an elliptic-curve key")
    key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))


def check_attestation(evidence: dict, root_pem: bytes, at: datetime | None) -> tuple[list[tuple[str, str]], ec.EllipticCurvePublicKey]:
    """Apple's enrolment statement. Returns the result lines and the attested public key (needed for the assertion)."""
    apple = evidence["apple"]
    lines: list[tuple[str, str]] = []
    obj = cbor2.loads(_b64(apple["attestation_b64"]))
    if obj.get("fmt") != "apple-appattest":
        raise Failed("attestation format is not apple-appattest")
    auth, x5c = obj["authData"], obj["attStmt"]["x5c"]
    certs = [x509.load_der_x509_certificate(c) for c in x5c]
    root = x509.load_pem_x509_certificate(root_pem)
    if len(certs) < 2:
        raise Failed("certificate chain too short")
    if certs[-1].issuer != root.subject:
        raise Failed("chain does not end at the root you supplied")
    for child, issuer in zip(certs, certs[1:]):
        if child.issuer != issuer.subject:
            raise Failed("certificate issuer does not match the next certificate")
        _signed_by(child, issuer)
    _signed_by(certs[-1], root)
    lines.append(("CHECKED", f"certificate chain ends at the supplied root (SHA-256 of root: {hashlib.sha256(root.public_bytes(serialization.Encoding.DER)).hexdigest()})"))
    if at is None:
        lines.append(("NOT CHECKED", "certificate validity windows (pass --at <time the key enrolled>)"))
    else:
        for cert in certs:
            if cert.not_valid_before_utc > at or cert.not_valid_after_utc < at:
                raise Failed(f"a certificate was not valid at {at.isoformat()}")
        lines.append(("CHECKED", f"every certificate was valid at {at.isoformat()}"))

    leaf = certs[0]
    ad = _auth_data(auth, attestation=True)
    nonce = hashlib.sha256(auth + hashlib.sha256(apple["challenge"].encode("utf-8")).digest()).digest()
    try:
        ext = leaf.extensions.get_extension_for_oid(APPLE_NONCE_OID).value.value
    except x509.ExtensionNotFound:
        raise Failed("leaf certificate has no Apple nonce extension") from None
    if not (ext.endswith(nonce) and ext[-34:-32] == b"\x04\x20"):
        raise Failed("Apple's nonce in the certificate does not match the challenge")
    lines.append(("CHECKED", "the certificate's nonce matches sha256(authData + sha256(challenge)): made over this challenge"))

    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise Failed("attested key is not P-256")
    raw = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id = _b64(apple["key_id"])
    if hashlib.sha256(raw).digest() != key_id or ad["credential_id"] != key_id:
        raise Failed("key id is not the hash of the attested key")
    lines.append(("CHECKED", "key id is the SHA-256 of the key Apple attested"))
    if ad["rp_id_hash"] != hashlib.sha256(apple["app_id"].encode("utf-8")).digest():
        raise Failed("authenticator data is for another app id")
    lines.append(("CHECKED", f"made for app id {apple['app_id']}"))
    if ad["counter"] != 0:
        raise Failed("attestation counter is not zero")
    if ad["aaguid"] not in (PROD_AAGUID, DEV_AAGUID):
        raise Failed("not an App Attest AAGUID")
    lines.append(("CHECKED", "App Attest " + ("production" if ad["aaguid"] == PROD_AAGUID else "DEVELOPMENT (sandbox) environment")))
    return lines, pub


def check_assertion(evidence: dict, key: ec.EllipticCurvePublicKey) -> list[tuple[str, str]]:
    """Apple's per-photo statement: the attested key signed this record hash."""
    apple, record_hash = evidence["apple"], evidence["record_hash"]
    if evidence.get("record", {}).get("record_hash") != record_hash:
        raise Failed("record_hash in the evidence is not the record's own hash")
    assertion = cbor2.loads(_b64(apple["assertion_b64"]))
    auth, signature = assertion["authenticatorData"], assertion["signature"]
    ad = _auth_data(auth, attestation=False)
    if ad["rp_id_hash"] != hashlib.sha256(apple["app_id"].encode("utf-8")).digest():
        raise Failed("assertion is for another app id")
    nonce = hashlib.sha256(auth + bytes.fromhex(record_hash)).digest()
    try:
        key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Failed("the attested key did not sign this record hash") from None
    return [("CHECKED", f"the attested key signed record hash {record_hash[:16]}… (assertion counter {ad['counter']})"),
            ("NOT CHECKED", "that the assertion counter only ever increases (needs every assertion from this key; the server tracks it)")]


def check(evidence: dict, root_pem: bytes, at: datetime | None = None) -> tuple[int, list[tuple[str, str]]]:
    apple = evidence.get("apple") or {}
    if not apple.get("kept"):
        return 3, [("NOT PRESENT", "Apple's evidence was not kept: " + str(apple.get("reason", "no reason given")))]
    lines: list[tuple[str, str]] = []
    try:
        att_lines, key = check_attestation(evidence, root_pem, at)
        lines += att_lines
        lines += check_assertion(evidence, key)
    except Failed as exc:
        return 2, lines + [("FAILED", str(exc))]
    except (KeyError, ValueError, TypeError, InvalidSignature, cbor2.CBORDecodeError) as exc:
        return 2, lines + [("FAILED", f"evidence is malformed or does not verify ({type(exc).__name__}: {exc})")]
    failed = any(tag == "FAILED" for tag, _ in lines)
    return (2 if failed else 0), lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check Apple's evidence for a Shield photo offline.")
    ap.add_argument("evidence", help="JSON from GET /shield/captures/<record_hash>/evidence")
    ap.add_argument("--root", required=True, help="Apple's App Attestation root certificate (PEM)")
    ap.add_argument("--at", help="time to judge certificate validity at, ISO 8601 (the time the key enrolled)")
    args = ap.parse_args(argv)
    at = datetime.fromisoformat(args.at.replace("Z", "+00:00")).astimezone(timezone.utc) if args.at else None
    with open(args.evidence, encoding="utf-8") as fh:
        evidence = json.load(fh)
    with open(args.root, "rb") as fh:
        root_pem = fh.read()
    code, lines = check(evidence, root_pem, at)
    for tag, text in lines:
        print(f"{tag:<11} {text}")
    return code


if __name__ == "__main__":
    sys.exit(main())
