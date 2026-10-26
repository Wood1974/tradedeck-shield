"""Share codes, and the compare-with-server check.

A photographer can let someone check a photo against the copy Shield stored when it was uploaded. They make a share
code for one photo; whoever holds the code and the ORIGINAL file can submit both, with no account, and learn whether
the file is the one Shield stored.

Privacy, by design
- Without a valid code nothing is revealed: a wrong, expired or revoked code and a code for a photo that is gone all
  answer the same `not_found`. A file alone never tells anyone whether Shield holds it.
- The answer is facts only. It never carries a name, an account id, the location, the note or the image itself. About
  the uploader it says one thing: whether the account passed the photo-ID and selfie check, and on what day.
- What a code shows is fixed when the code is made (`scope`). Codes made before timing evidence existed (scope 1) never
  show it; codes made after (scope 2) add two timing facts and nothing else: the clock-check label, and whether an outside
  time-stamp covers the photo. The clock-check notes and the job-start window are never in the answer.
- A code is 26 random characters (about 128 bits), shown once and kept only as an HMAC. It can be revoked and expires.
- The submitted file is read in memory, compared and dropped. Nothing from the person checking is kept; the log
  records only that a check happened and whether it matched.

What a match does and does not show
- It shows the file is identical to the one Shield stored at the upload time on Shield's clock, and that the stored
  record's device signature still verifies.
- It does not show that the scene is true, who held the signing key (the key is not tied to the account), or the time
  the photo was taken (that is the phone's clock).
- A copy that went through email or a messaging app is usually recompressed. It is a different file and will not match.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from collections import deque
from datetime import datetime, timezone

from . import captures, outside_time
from .custody_chain import event_hash
from .local_identity import LocalIdentity, init_once

DEFAULT_DAYS = 30
MAX_DAYS = 90
# No 0, O, 1, I or L, so a code read aloud or from a screenshot is not misread.
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 26
NOT_FOUND = "not_found"
HOURLY_COMPARE_LIMIT = 600  # across everyone: a guard against floods, not a per-person allowance
_compare_times: deque = deque()

LIMITATIONS = [
    "A match shows this file is identical to the one Shield stored; it does not show the scene is true or staged.",
    "The signing key is not tied to the account: 'uploaded by an ID-checked account' is not 'signed by the person'.",
    "The capture time is the phone's clock. The upload time is Shield's clock.",
    "A copy sent by email or a messaging app is usually recompressed and will not match. Use the original file.",
]
# What a code made at each scope may show. A code never gains scope after it is made.
SCOPE_BASIC = 1
SCOPE_TIMING = 2
TIMING_LIMITATIONS = [
    "The clock check compares the phone's own clocks with each other. It is not a timestamp, and 'consistent' does not show when the photo was taken.",
    "An outside time-stamp shows that the photo's record existed by that time. It does not show when the photo was taken.",
]
MISMATCH_HINT = (
    "This file is not the one Shield stored. A photo sent by email or a messaging app is usually recompressed, which "
    "changes it. Ask for the original file, sent as a file or attachment, not as a picture in a message."
)


@init_once
def _init(local: LocalIdentity) -> None:
    captures._init(local)
    outside_time._init(local)
    with local.db() as db:
        db.executescript("""
          CREATE TABLE IF NOT EXISTS capture_shares (
            id TEXT PRIMARY KEY, capture_id TEXT NOT NULL REFERENCES captures(id), account_id TEXT NOT NULL,
            code_hmac TEXT NOT NULL UNIQUE, created_at REAL NOT NULL, expires_at REAL NOT NULL, revoked_at REAL,
            scope INTEGER NOT NULL DEFAULT 1
          );
          CREATE INDEX IF NOT EXISTS capture_shares_capture ON capture_shares(capture_id);
          CREATE TABLE IF NOT EXISTS compare_log (
            id TEXT PRIMARY KEY, share_id TEXT NOT NULL, result TEXT NOT NULL, event_at TEXT NOT NULL,
            previous_hash TEXT, event_hash TEXT NOT NULL
          );
        """)
        # A table made before timing evidence existed has no scope column; its codes read as scope 1 (the original promise).
        if "scope" not in {row[1] for row in db.execute("PRAGMA table_info(capture_shares)").fetchall()}:
            db.execute("ALTER TABLE capture_shares ADD COLUMN scope INTEGER NOT NULL DEFAULT 1")


def normalize(code: str) -> str:
    """Upper case, letters and digits only, so spaces, dashes and case do not matter."""
    return "".join(ch for ch in str(code).upper() if ch.isalnum())


def _hmac(normalized: str) -> str:
    return hmac.new(LocalIdentity._secret().encode("utf-8"), f"share:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()


def display(code: str) -> str:
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z") if ts else None


def enforce_compare_limit() -> bool:
    """False when the whole service has had too many checks this hour."""
    now = time.time()
    while _compare_times and _compare_times[0] < now - 3600:
        _compare_times.popleft()
    if len(_compare_times) >= HOURLY_COMPARE_LIMIT:
        return False
    _compare_times.append(now)
    return True


def create(local: LocalIdentity, account_id: str, record_hash: str, days: int = DEFAULT_DAYS) -> dict | None:
    """A new share code for one of this account's uploaded photos, or None when it is not theirs. The only time the plain code exists."""
    if type(days) is not int or not 1 <= days <= MAX_DAYS:
        raise ValueError("share_request_invalid")
    if not captures._is_hex64(record_hash):
        return None
    _init(local)
    with local.db() as db:
        capture = db.execute("SELECT id FROM captures WHERE account_id=? AND record_hash=?", (account_id, record_hash)).fetchone()
        if not capture:
            return None
        code = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
        now, share_id = time.time(), str(uuid.uuid4())
        db.execute("INSERT INTO capture_shares(id,capture_id,account_id,code_hmac,created_at,expires_at,scope) VALUES(?,?,?,?,?,?,?)",
                   (share_id, capture["id"], account_id, _hmac(code), now, now + days * 86400, SCOPE_TIMING))
    return {"id": share_id, "code": display(code), "expires_at": _iso(now + days * 86400)}


def list_for(local: LocalIdentity, account_id: str, record_hash: str) -> list[dict] | None:
    if not captures._is_hex64(record_hash):
        return None
    _init(local)
    now = time.time()
    with local.db() as db:
        capture = db.execute("SELECT id FROM captures WHERE account_id=? AND record_hash=?", (account_id, record_hash)).fetchone()
        if not capture:
            return None
        rows = db.execute("SELECT * FROM capture_shares WHERE capture_id=? AND account_id=? ORDER BY created_at DESC", (capture["id"], account_id)).fetchall()
    return [{"id": r["id"], "created_at": _iso(r["created_at"]), "expires_at": _iso(r["expires_at"]),
             "revoked": r["revoked_at"] is not None, "active": r["revoked_at"] is None and r["expires_at"] > now,
             "timing": r["scope"] >= SCOPE_TIMING} for r in rows]


def revoke(local: LocalIdentity, account_id: str, share_id: str) -> bool:
    _init(local)
    with local.db() as db:
        cursor = db.execute("UPDATE capture_shares SET revoked_at=? WHERE id=? AND account_id=? AND revoked_at IS NULL",
                            (time.time(), share_id, account_id))
        return cursor.rowcount == 1


def _uploader_status(account_id: str, received_at: float) -> dict:
    """Only whether the account passed the ID check and when. No name, no document data, no account id."""
    from .identity_api import _db as identity_db
    try:
        with identity_db() as db:
            session = db.execute(
                "SELECT livemode, verified_at FROM identity_sessions WHERE account_id=? AND status='verified' AND verified_at IS NOT NULL "
                "ORDER BY verified_at DESC LIMIT 1", (account_id,)).fetchone()
            note = db.execute("SELECT 1 FROM note_attestations WHERE account_id=? AND revoked_at IS NULL LIMIT 1", (account_id,)).fetchone()
    except Exception:
        session = note = None
    if not session or not note:
        return {"id_check": "not_verified"}
    return {
        "id_check": "passed" if session["livemode"] == 1 else "test_mode",
        "on": datetime.fromtimestamp(session["verified_at"], timezone.utc).date().isoformat(),
        "before_upload": session["verified_at"] <= received_at,
    }


def compare(local: LocalIdentity, code: str, supplied: bytes) -> dict | None:
    """Compares the supplied file with the stored photo for this code. None when the code is not good."""
    normalized = normalize(code)
    if len(normalized) != CODE_LENGTH:
        return None
    _init(local)
    now = time.time()
    with local.db() as db:
        row = db.execute(
            "SELECT s.id AS share_id, s.expires_at, s.revoked_at, s.scope, c.* FROM capture_shares s JOIN captures c ON c.id = s.capture_id "
            "WHERE s.code_hmac=?", (_hmac(normalized),)).fetchone()
    if not row or row["revoked_at"] is not None or row["expires_at"] <= now:
        return None

    stored_ok = False
    path = captures._photo_path(row["account_id"], row["record_hash"])
    if path.is_file():
        stored_ok = hashlib.sha256(path.read_bytes()).hexdigest() == row["photo_sha256"]
    supplied_ok = hashlib.sha256(supplied).hexdigest() == row["photo_sha256"]
    try:
        import json
        record = json.loads(row["record_json"])
        record_ok = (captures.record_hash_of(record, row["prev_hash"]) == row["record_hash"]
                     and captures.signature_valid(row["public_key_b64"], captures.signing_message(record, row["prev_hash"]), row["signature_der_b64"]))
    except Exception:
        record_ok = False
    matched = supplied_ok and stored_ok and record_ok

    result = {
        "match": matched,
        "uploaded_at": _iso(row["received_at"]),
        "checks": {"supplied_equals_stored": supplied_ok, "stored_original_intact": stored_ok, "record_signature_valid": record_ok},
        "device_check": {"status": "verified" if row["attest_trusted"] else "not_verified", "detail": row["attest_status"]},
        "uploader": _uploader_status(row["account_id"], row["received_at"]),
        "limitations": LIMITATIONS,
    }
    if row["scope"] >= SCOPE_TIMING:
        # Two facts, both worked out before this request (the label when the photo was uploaded, the stamp when it was taken):
        # no notes, no job-start window, nothing that needs account-sized work on this public route.
        cover = outside_time.coverage_for(local, row["account_id"], [row["record_hash"]]).get(row["record_hash"])
        result["timing"] = {"clock_check": {"label": row["time_label"] or "NOT CHECKED"}, "outside_time": outside_time.view(cover)}
        result["limitations"] = LIMITATIONS + TIMING_LIMITATIONS
    if not supplied_ok:
        result["hint"] = MISMATCH_HINT
    _log(local, row["share_id"], "match" if matched else "no_match")
    return result


def _log(local: LocalIdentity, share_id: str, outcome: str) -> None:
    """Appends to a hash-chained log (the older custody-chain code). Result and time only: no file, no address."""
    at = _iso(time.time())
    with local.db() as db:
        last = db.execute("SELECT event_hash FROM compare_log ORDER BY rowid DESC LIMIT 1").fetchone()
        previous = last["event_hash"] if last else None
        digest = event_hash(previous, "compare", at, None, {"share_id": share_id, "result": outcome})
        db.execute("INSERT INTO compare_log(id,share_id,result,event_at,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
                   (str(uuid.uuid4()), share_id, outcome, at, previous, digest))
