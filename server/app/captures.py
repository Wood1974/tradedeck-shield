"""Stored photos: the phone's sealed records, checked on arrival and kept for the account that took them.

A phone seals each photo offline (a signed, hash-linked record, plus an optional Apple App Attest assertion). When it
has signal and a signed-in account it uploads the record and the original JPEG here. Nothing is stored unless it checks:

- the record's bytes reproduce its record_hash (so no signed field was edited),
- SHA-256 of the whole uploaded file equals the signed photo_sha256 (the image is the one that was signed),
- the device signature verifies over the record with the key sent along.

Only the account that uploaded a photo can list or read it. A photo can be uploaded twice safely (the second answers
"already"). Failing evidence is refused, never stored half-checked; the phone keeps its copy.

What this does not prove: who holds the signing key (the device key is not tied to the account), that the scene is
true, or the time beyond what the phone's clock said. The Apple assertion is checked when one is sent and its result
is stored beside the photo as its own field; a failed or missing assertion never blocks the photo.

The record format is a port of the phone's (shield-app/src/capture/record.ts) and is held to its frozen vectors.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import tickets, time_audit
from .local_identity import LocalIdentity

RECORD_VERSION = 1
JS_SAFE_INT = 2 ** 53 - 1
MAX_TEXT = 512
RECORD_FIELDS = (
    "version", "checkpoint_id", "photo_sha256", "ticket_id", "wall_time_ms", "monotonic_ms", "boot_id", "boot_count",
    "gnss_time_ms", "location_simulated", "sensor_hash", "depth_hash", "depth_present", "flags",
)
REQUIRED = {"version", "checkpoint_id", "photo_sha256", "ticket_id", "wall_time_ms", "monotonic_ms", "flags"}
INT_FIELDS = {"version", "wall_time_ms", "monotonic_ms", "boot_count", "gnss_time_ms", "flags"}
NON_NEGATIVE = {"version", "monotonic_ms", "boot_count", "flags"}
BOOL_FIELDS = {"location_simulated", "depth_present"}
HEX_FIELDS = {"photo_sha256", "sensor_hash", "depth_hash"}
TEXT_FIELDS = {"checkpoint_id", "ticket_id", "boot_id"}
LINKS = {"prev_hash", "record_hash"}


class Refused(ValueError):
    """The upload is not stored. The message is a stable code the phone can show."""


def _is_hex64(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _field(key: str, value):
    if key in BOOL_FIELDS:
        if type(value) is not bool:
            raise Refused("record_invalid")
        return value
    if key in HEX_FIELDS:
        if not _is_hex64(value):
            raise Refused("record_invalid")
        return value
    if key in INT_FIELDS:
        if type(value) is not int or abs(value) > JS_SAFE_INT or (key in NON_NEGATIVE and value < 0):
            raise Refused("record_invalid")
        return value
    if key in TEXT_FIELDS:
        if not isinstance(value, str) or not value or len(value) > MAX_TEXT:
            raise Refused("record_invalid")
        return value
    raise Refused("record_invalid")


def canonical_bytes(record: dict) -> bytes:
    """The signed bytes of a record: only the signed fields, nulls dropped, keys sorted, ASCII, no spaces."""
    if not isinstance(record, dict):
        raise Refused("record_invalid")
    unknown = set(record) - set(RECORD_FIELDS) - LINKS
    if unknown:  # a field the signature would not cover
        raise Refused("record_invalid")
    if record.get("version") != RECORD_VERSION:
        raise Refused("record_invalid")
    for key in REQUIRED:
        if record.get(key) is None:
            raise Refused("record_invalid")
    present, digest = record.get("depth_present"), record.get("depth_hash")
    if (present is True and digest is None) or (digest is not None and present is not True):
        raise Refused("record_invalid")
    out = {key: _field(key, record[key]) for key in RECORD_FIELDS if record.get(key) is not None}
    return json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def signing_message(record: dict, prev_hash: str) -> bytes:
    return canonical_bytes(record) + b"|" + prev_hash.encode("utf-8")


def record_hash_of(record: dict, prev_hash: str) -> str:
    return hashlib.sha256(signing_message(record, prev_hash)).hexdigest()


def strict_b64(value) -> bytes:
    """Decodes base64 only when it is the canonical encoding of exactly those bytes."""
    if not isinstance(value, str) or not value:
        raise Refused("photo_invalid")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise Refused("photo_invalid") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise Refused("photo_invalid")
    return raw


def signature_valid(public_key_b64: str, message: bytes, signature_der_b64: str) -> bool:
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(public_key_b64, validate=True))
        key.verify(base64.b64decode(signature_der_b64, validate=True), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def max_photo_bytes() -> int:
    return int(os.getenv("SHIELD_MAX_PHOTO_BYTES", "15728640"))


def quota_bytes() -> int:
    return int(os.getenv("SHIELD_ACCOUNT_QUOTA_MB", "1024")) * 1024 * 1024


def storage_root() -> Path:
    return Path(os.getenv("SHIELD_STORAGE_ROOT", "./storage")) / "captures"


def _init(local: LocalIdentity) -> None:
    with local.db() as db:
        db.executescript("""
          CREATE TABLE IF NOT EXISTS captures (
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES local_accounts(id),
            record_hash TEXT NOT NULL, prev_hash TEXT NOT NULL,
            ticket_id TEXT NOT NULL, checkpoint_id TEXT NOT NULL,
            photo_sha256 TEXT NOT NULL, photo_bytes INTEGER NOT NULL,
            record_json TEXT NOT NULL, signature_der_b64 TEXT NOT NULL, public_key_b64 TEXT NOT NULL,
            attest_key_id TEXT, attest_status TEXT NOT NULL, attest_trusted INTEGER NOT NULL DEFAULT 0,
            received_at REAL NOT NULL,
            time_label TEXT, time_notes TEXT, ticket_hash TEXT,
            UNIQUE(account_id, record_hash)
          );
        """)
        # A table made before the clock check existed has no such columns; its rows keep NULL, shown as NOT CHECKED.
        have = {row[1] for row in db.execute("PRAGMA table_info(captures)").fetchall()}
        for column in ("time_label", "time_notes", "ticket_hash"):
            if column not in have:
                db.execute(f"ALTER TABLE captures ADD COLUMN {column} TEXT")


def _photo_path(account_id: str, record_hash: str) -> Path:
    # Both parts are checked as a UUID and 64 hex characters before they get here, so neither can escape the folder.
    return storage_root() / account_id / f"{record_hash}.jpg"


def _view(row, ticket: dict | None = None) -> dict:
    return {
        "id": row["id"], "record_hash": row["record_hash"], "ticket_id": row["ticket_id"], "checkpoint_id": row["checkpoint_id"],
        "photo_sha256": row["photo_sha256"], "bytes": row["photo_bytes"], "received_at": row["received_at"],
        "integrity": "verified",
        "attest": {"status": row["attest_status"], "trusted": bool(row["attest_trusted"])},
        "time": {"label": row["time_label"] or time_audit.NOT_CHECKED,
                 "notes": json.loads(row["time_notes"]) if row["time_notes"] else (["stored before the clock check existed"] if not row["time_label"] else [])},
        "ticket": ticket or {"origin": "local"},
    }


def ingest(local: LocalIdentity, verifier, account_id: str, upload: dict) -> dict:
    """Checks one upload and stores it. Raises Refused (nothing stored) when any check fails."""
    _init(local)
    record, prev_hash, rec_hash = upload.get("record"), None, None
    if not isinstance(record, dict):
        raise Refused("record_invalid")
    prev_hash, rec_hash = record.get("prev_hash"), record.get("record_hash")
    if not _is_hex64(prev_hash) or not _is_hex64(rec_hash):
        raise Refused("record_invalid")
    if record_hash_of(record, prev_hash) != rec_hash:
        raise Refused("record_hash_mismatch")
    raw_b64 = upload.get("photo_b64")
    if isinstance(raw_b64, str) and len(raw_b64) > max_photo_bytes() * 4 // 3 + 8:
        raise Refused("photo_too_large")
    photo = strict_b64(raw_b64)
    if len(photo) > max_photo_bytes():
        raise Refused("photo_too_large")
    if hashlib.sha256(photo).hexdigest() != record["photo_sha256"]:
        raise Refused("photo_hash_mismatch")
    signature, public_key = upload.get("signature_der_b64"), upload.get("public_key_uncompressed_b64")
    if not isinstance(signature, str) or not isinstance(public_key, str) or not signature_valid(public_key, signing_message(record, prev_hash), signature):
        raise Refused("signature_invalid")

    with local.db() as db:
        existing = db.execute("SELECT * FROM captures WHERE account_id=? AND record_hash=?", (account_id, rec_hash)).fetchone()
        if existing:
            return {**_view(existing, ticket_view(local, account_id, existing["ticket_hash"])), "already": True}
        used = db.execute("SELECT COALESCE(SUM(photo_bytes),0) FROM captures WHERE account_id=?", (account_id,)).fetchone()[0]
        if used + len(photo) > quota_bytes():
            raise Refused("quota_exceeded")

    key_id, assertion = upload.get("app_attest_key_id"), upload.get("app_attest_assertion_b64")
    if key_id and assertion and verifier is not None:
        # Apple's statement about this record hash, checked against the key this account enrolled. It never blocks.
        result = verifier.verify_assertion(assertion, rec_hash, key_id, account_id=account_id)
        attest_status, trusted = ("verified" if result.get("trusted") else str(result.get("status"))), bool(result.get("trusted"))
    else:
        attest_status, trusted = "none", False

    now = time.time()
    with local.db() as db:
        before = db.execute("SELECT record_json, ticket_hash FROM captures WHERE account_id=? AND record_hash=?", (account_id, prev_hash)).fetchone()
    # A chain's first photo links to a server ticket when it was started with one: that ticket (for the same ticket id)
    # anchors the chain and its clock is the baseline. Later photos inherit the anchor from the record before them.
    started = tickets.by_hash(local, account_id, prev_hash)
    if started and started["ticket_id"] != record["ticket_id"]:
        started = None
    anchor = started["ticket_hash"] if started else (before["ticket_hash"] if before else None)
    baseline = started["clock"] if started else (json.loads(before["record_json"]) if before else None)
    # Never blocks a photo: the result is stored beside it, like the Apple check.
    clock = time_audit.assess(record, baseline, int(now * 1000))

    path = _photo_path(account_id, rec_hash)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".part")
    temp.write_bytes(photo)
    os.replace(temp, path)
    row_id = str(uuid.uuid4())
    try:
        with local.db() as db:
            db.execute(
                "INSERT INTO captures(id,account_id,record_hash,prev_hash,ticket_id,checkpoint_id,photo_sha256,photo_bytes,record_json,"
                "signature_der_b64,public_key_b64,attest_key_id,attest_status,attest_trusted,received_at,time_label,time_notes,ticket_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row_id, account_id, rec_hash, prev_hash, record["ticket_id"], record["checkpoint_id"], record["photo_sha256"], len(photo),
                 json.dumps(record, sort_keys=True), signature, public_key, key_id, attest_status, int(trusted), now, clock["label"], json.dumps(clock["notes"]), anchor))
            row = db.execute("SELECT * FROM captures WHERE id=?", (row_id,)).fetchone()
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return {**_view(row, ticket_view(local, account_id, anchor)), "already": False}


def ticket_view(local: LocalIdentity, account_id: str, ticket_hash: str | None) -> dict:
    """Whether a server-signed ticket anchors this record's chain, and the window it started in."""
    started = tickets.by_hash(local, account_id, ticket_hash) if ticket_hash else None
    if not started:
        return {"origin": "local"}
    iso = lambda ms: datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
    return {"origin": "server", "after": iso(started["server_time_ms"]), "before": iso(started["countersigned_at_ms"])}


def list_for(local: LocalIdentity, account_id: str, limit: int = 200) -> list[dict]:
    _init(local)
    with local.db() as db:
        rows = db.execute("SELECT * FROM captures WHERE account_id=? ORDER BY received_at DESC LIMIT ?", (account_id, limit)).fetchall()
    return [_view(r, ticket_view(local, account_id, r["ticket_hash"])) for r in rows]


def read_photo(local: LocalIdentity, account_id: str, record_hash: str) -> bytes | None:
    """The stored JPEG for this account's record, or None. Raises Refused('stored_photo_corrupt') if the file changed."""
    if not _is_hex64(record_hash):
        return None
    _init(local)
    with local.db() as db:
        row = db.execute("SELECT photo_sha256 FROM captures WHERE account_id=? AND record_hash=?", (account_id, record_hash)).fetchone()
    if not row:
        return None
    path = _photo_path(account_id, record_hash)
    if not path.is_file():
        raise Refused("stored_photo_missing")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != row["photo_sha256"]:
        raise Refused("stored_photo_corrupt")
    return data
