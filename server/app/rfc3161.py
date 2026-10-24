"""RFC 3161 time-stamp requests and replies: build a request, and check a reply before it is kept.

A time-stamp authority (TSA) signs "this hash existed by this time". Only a hash is sent. What is checked here, in order:
the reply says granted; its message imprint and nonce are the ones we sent; the signed attributes bind the time-stamp info; the
signer's certificate (sent with the reply) is a time-stamping certificate valid at that time; the signature verifies with it.
Whether that certificate chains to a root we trust is checked only when trusted roots are supplied (`trusted_pem`); without them
the result says `chain_checked: False`. Anyone can check a stored token later with `openssl ts -verify`.

What a valid token shows: the TSA says the hash existed by gen_time. It does not show who made the photo or that the scene is
true, and it is only as good as the TSA's clock and the roots you trust.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import timezone

from asn1crypto import algos, cms, core, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

TSTINFO_OID = "1.2.840.113549.1.9.16.1.4"
_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


class TimestampInvalid(ValueError):
    """The reply is not kept. The message is a short stable reason."""


def new_nonce() -> int:
    return secrets.randbits(63)


def build_request(imprint: bytes, nonce: int) -> bytes:
    if len(imprint) != 32:
        raise ValueError("imprint must be a SHA-256 digest")
    return tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": imprint},
        "nonce": nonce,
        "cert_req": True,
    }).dump()


def _certs(signed_data: cms.SignedData) -> list[x509.Certificate]:
    out = []
    for c in signed_data["certificates"] or []:
        if c.name == "certificate":
            out.append(x509.load_der_x509_certificate(c.chosen.dump()))
    return out


def _signer_cert(signer_info: cms.SignerInfo, certs: list[x509.Certificate]) -> x509.Certificate:
    sid = signer_info["sid"]
    for cert in certs:
        if sid.name == "issuer_and_serial_number":
            if cert.serial_number == sid.chosen["serial_number"].native and cert.issuer.public_bytes() == sid.chosen["issuer"].dump():
                return cert
        elif sid.name == "subject_key_identifier":
            try:
                ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            except x509.ExtensionNotFound:
                continue
            if ski == sid.chosen.native:
                return cert
    raise TimestampInvalid("signer_certificate_missing")


def _verify_signature(cert: x509.Certificate, digest_name: str, signature_algorithm: str, signature: bytes, signed: bytes) -> None:
    hash_cls = _HASHES.get(digest_name)
    if hash_cls is None:
        raise TimestampInvalid("digest_algorithm_unsupported")
    key = cert.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            if signature_algorithm.endswith("_rsa") or signature_algorithm in ("rsassa_pkcs1v15", "rsa"):
                key.verify(signature, signed, padding.PKCS1v15(), hash_cls())
            else:
                raise TimestampInvalid("signature_algorithm_unsupported")
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(hash_cls()))
        else:
            raise TimestampInvalid("signature_algorithm_unsupported")
    except InvalidSignature:
        raise TimestampInvalid("signature_invalid") from None


def _chain_checked(signer: x509.Certificate, others: list[x509.Certificate], roots: list[x509.Certificate], at) -> None:
    """Walks signer -> intermediates -> a trusted root, checking each signature and validity at the time-stamp's time."""
    current, seen = signer, 0
    while seen < 8:
        seen += 1
        if not (current.not_valid_before_utc <= at <= current.not_valid_after_utc):
            raise TimestampInvalid("certificate_not_valid_at_time")
        for root in roots:
            try:
                current.verify_directly_issued_by(root)
                if root.not_valid_before_utc <= at <= root.not_valid_after_utc:
                    return
            except (ValueError, TypeError, InvalidSignature):
                continue
        parent = None
        for cand in others:
            try:
                current.verify_directly_issued_by(cand)
                parent = cand
                break
            except (ValueError, TypeError, InvalidSignature):
                continue
        if parent is None:
            raise TimestampInvalid("chain_not_trusted")
        current = parent
    raise TimestampInvalid("chain_not_trusted")


def load_roots(pem: bytes | None) -> list[x509.Certificate]:
    return list(x509.load_pem_x509_certificates(pem)) if pem else []


def check_reply(reply: bytes, imprint: bytes, nonce: int, trusted_roots: list[x509.Certificate] | None = None) -> dict:
    """Returns {gen_time, serial, policy, chain_checked} or raises TimestampInvalid. `gen_time` is a UTC datetime."""
    try:
        # The status is read on its own first: a refusal carries no token, and must read as a refusal, not as garbage.
        status = tsp.PKIStatusInfo.load(core.Sequence.load(reply).contents)["status"].native
    except (ValueError, TypeError, KeyError):
        raise TimestampInvalid("reply_unreadable") from None
    if status not in ("granted", "granted_with_mods"):
        raise TimestampInvalid("not_granted")
    try:
        resp = tsp.TimeStampResp.load(reply)
        token = resp["time_stamp_token"]
        signed_data = token["content"]
        encap = signed_data["encap_content_info"]
        if encap["content_type"].dotted != TSTINFO_OID:
            raise TimestampInvalid("not_a_timestamp_token")
        tst_octets = encap["content"].contents  # the exact bytes the signature covers
        tst = tsp.TSTInfo.load(tst_octets)
        info = tst.native
        if len(signed_data["signer_infos"]) != 1:
            raise TimestampInvalid("signer_count_unsupported")
        signer_info = signed_data["signer_infos"][0]
    except TimestampInvalid:
        raise
    except (ValueError, TypeError, KeyError):
        raise TimestampInvalid("reply_unreadable") from None

    mi = info["message_imprint"]
    if mi["hash_algorithm"]["algorithm"] != "sha256" or mi["hashed_message"] != imprint:
        raise TimestampInvalid("imprint_mismatch")
    if info.get("nonce") != nonce:
        raise TimestampInvalid("nonce_mismatch")

    digest_name = signer_info["digest_algorithm"]["algorithm"].native
    attrs = signer_info["signed_attrs"]
    if not attrs or isinstance(attrs, core.Void):
        raise TimestampInvalid("signed_attributes_missing")
    by_name = {a["type"].native: a["values"][0] for a in attrs}
    if by_name.get("content_type") is None or by_name["content_type"].dotted != TSTINFO_OID:
        raise TimestampInvalid("signed_attributes_wrong")
    hash_cls = _HASHES.get(digest_name)
    if hash_cls is None:
        raise TimestampInvalid("digest_algorithm_unsupported")
    h = hashes.Hash(hash_cls())
    h.update(tst_octets)
    if by_name.get("message_digest") is None or by_name["message_digest"].native != h.finalize():
        raise TimestampInvalid("message_digest_mismatch")

    certs = _certs(signed_data)
    signer = _signer_cert(signer_info, certs)
    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        raise TimestampInvalid("certificate_not_for_timestamping") from None
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        raise TimestampInvalid("certificate_not_for_timestamping")

    signed_bytes = b"\x31" + attrs.dump(force=True)[1:]  # the attributes are signed as a SET, not as [0] IMPLICIT
    _verify_signature(signer, digest_name, signer_info["signature_algorithm"]["algorithm"].native, signer_info["signature"].native, signed_bytes)

    gen_time = info["gen_time"].astimezone(timezone.utc)
    if not (signer.not_valid_before_utc <= gen_time <= signer.not_valid_after_utc):
        raise TimestampInvalid("certificate_not_valid_at_time")
    chain = False
    if trusted_roots:
        _chain_checked(signer, [c for c in certs if c != signer], trusted_roots, gen_time)
        chain = True
    return {"gen_time": gen_time, "serial": info.get("serial_number"), "policy": info.get("policy"), "chain_checked": chain}


def chain_head_imprint(record_hash: str) -> bytes:
    """What is sent for a chain head: a domain-separated hash of its record hash. Anyone holding the head can recompute it."""
    return hashlib.sha256(b"shield-chain-head-v1|" + record_hash.encode("ascii")).digest()
