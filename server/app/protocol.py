"""TradeDeck Shield Evidence Core Protocol v1.

This module contains the protocol primitives only. It intentionally has no
storage, HTTP, database, or platform-attestation dependencies.
"""
from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Mapping

PROTOCOL_VERSION = "shield-evidence-v1"
CHALLENGE_TTL_SECONDS = 120


class LocationVerdict(StrEnum):
    CONSISTENT = "consistent"
    FLAG = "flag"
    REJECT = "reject"


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name}_required")
    return value


def sha256_bytes(data: bytes) -> str:
    """SHA-256 of the exact bytes received/captured."""
    return hashlib.sha256(data).hexdigest()


def canonical_note(location_stated: str, purpose: str) -> bytes:
    """Return the canonical UTF-8 bytes for a capture note.

    The note is created in the same capture session as the photograph.
    Whitespace around the two human-entered fields is not evidence-bearing;
    internal whitespace and Unicode content are preserved.
    """
    location = _require_text("location_stated", location_stated).strip()
    why = _require_text("purpose", purpose).strip()
    if not location:
        raise ValueError("no_location_stated")
    if not why:
        raise ValueError("no_purpose")
    return json.dumps(
        {"location_stated": location, "purpose": why},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def note_sha256(location_stated: str, purpose: str) -> str:
    return sha256_bytes(canonical_note(location_stated, purpose))


def bind_payload(
    photo_sha256: str,
    note_sha256: str,
    job_id: str,
    point_id: str,
    nonce: str,
    account_id: str,
) -> bytes:
    """Exact v1 bind payload.

    The locked protocol is concatenation without separators or length
    prefixes: SHA-256(photoHash || noteHash || jobId || pointId || nonce ||
    accountId). The two hashes are lowercase hex strings.
    """
    fields = (
        _require_text("photo_sha256", photo_sha256),
        _require_text("note_sha256", note_sha256),
        _require_text("job_id", job_id),
        _require_text("point_id", point_id),
        _require_text("nonce", nonce),
        _require_text("account_id", account_id),
    )
    return "".join(fields).encode("utf-8")


def bind_hash(
    photo_sha256: str,
    note_sha256: str,
    job_id: str,
    point_id: str,
    nonce: str,
    account_id: str,
) -> str:
    return sha256_bytes(bind_payload(photo_sha256, note_sha256, job_id, point_id, nonce, account_id))


def validate_hash(value: str, field: str = "hash") -> str:
    value = _require_text(field, value).lower()
    if len(value) != 64:
        raise ValueError(f"{field}_invalid")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field}_invalid") from exc
    return value


def validate_capture_identity(job_id: str, point_id: str, nonce: str, account_id: str) -> None:
    _require_text("job_id", job_id)
    _require_text("point_id", point_id)
    _require_text("nonce", nonce)
    _require_text("account_id", account_id)


def capture_bind(
    photo_bytes: bytes,
    location_stated: str,
    purpose: str,
    job_id: str,
    point_id: str,
    nonce: str,
    account_id: str,
) -> dict[str, str]:
    """Build the complete deterministic evidence-core hash set."""
    validate_capture_identity(job_id, point_id, nonce, account_id)
    photo_hash = sha256_bytes(photo_bytes)
    note_hash = note_sha256(location_stated, purpose)
    return {
        "photo_sha256": photo_hash,
        "note_sha256": note_hash,
        "bind_hash": bind_hash(photo_hash, note_hash, job_id, point_id, nonce, account_id),
    }


def protocol_metadata() -> Mapping[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "challenge_ttl_seconds": CHALLENGE_TTL_SECONDS,
        "bind": "SHA-256(photoHash || noteHash || jobId || pointId || nonce || accountId)",
        "location_verdicts": [v.value for v in LocationVerdict],
        "server_written_at": True,
    }
