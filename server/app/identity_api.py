"""ID check + signed photographer note, for the Shield phone app (standalone: Shield-owned accounts, no Supabase).

Flow: consent -> /identity/start (Stripe Identity hosted check: document + live selfie match) ->
/identity/status (server asks Stripe, never trusts the client) -> /identity/note (device-signed
statement, accepted only after Stripe reports `verified`).

Test mode: an account whose email is listed in IDENTITY_TEST_MODE_EMAILS (the owner, who may have no ID to use) runs
the check against Stripe test mode with STRIPE_TEST_SECRET_KEY. Such a check passes with Stripe's test documents, so
its session is stored with livemode=0 and its receipt carries a signed `testMode: true`; the phone app and the public
lookup treat it as a test, never as a confirmed real check. Every other account is always live.

Privacy: ID and selfie images never reach this service; Stripe holds them. We keep only the session id, its status,
the consent record and the signed note. No name or document data is stored.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import stripe
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .auth import actor_for
from .identity_core import STATEMENT, STATEMENT_VERSION, load_receipt_key, make_receipt, receipt_public, statement_sha256, verify_note

log = logging.getLogger(__name__)
router = APIRouter(prefix="/identity")

CONSENT_VERSION = "1"
# Each new session can cost money at Stripe, so one account cannot start unlimited checks.
MAX_ID_CHECKS_PER_DAY = 5
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TEST_KEY_PREFIXES = ("sk_test_", "rk_test_")


def _err(code: str, http_status: int, **extra) -> JSONResponse:
    # The phone app reads `error`, so errors here use that key rather than FastAPI's default `detail`.
    return JSONResponse({"error": code, **extra}, status_code=http_status)


def _path() -> str:
    url = os.getenv("SHIELD_DATABASE_URL", "sqlite:///./shield.db")
    if not url.startswith("sqlite:///"):
        raise RuntimeError("identity_requires_sqlite_database")
    return url.removeprefix("sqlite:///")


@contextmanager
def _db():
    con = sqlite3.connect(_path(), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
      CREATE TABLE IF NOT EXISTS identity_sessions (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, stripe_session_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL, livemode INTEGER NOT NULL DEFAULT 1,
        consent_at REAL NOT NULL, consent_version TEXT NOT NULL,
        created_at REAL NOT NULL, updated_at REAL, verified_at REAL
      );
      CREATE INDEX IF NOT EXISTS identity_sessions_account ON identity_sessions(account_id, created_at);
      CREATE TABLE IF NOT EXISTS note_attestations (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES identity_sessions(id),
        device_seal_id TEXT NOT NULL, device_public_key TEXT NOT NULL, statement_version TEXT NOT NULL,
        note_payload TEXT NOT NULL, note_sha256 TEXT NOT NULL UNIQUE, signature TEXT NOT NULL,
        signed_at TEXT NOT NULL, receipt TEXT NOT NULL, created_at REAL NOT NULL, revoked_at REAL
      );
    """)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _test_key() -> str | None:
    """The Stripe test-mode key from the environment, or None. A live key here is refused, never used."""
    key = os.environ.get("STRIPE_TEST_SECRET_KEY", "").strip()
    return key if key.startswith(_TEST_KEY_PREFIXES) else None


def _email_of(account_id: str) -> str | None:
    from .local_identity import identity
    with identity().db() as db:
        row = db.execute("SELECT email FROM local_accounts WHERE id=?", (account_id,)).fetchone()
    return row["email"] if row else None


def _test_key_for(account_id: str) -> str | None:
    """The test key, only for an account on the owner allowlist. Everyone else is always live."""
    allowed = {e.strip().lower() for e in os.environ.get("IDENTITY_TEST_MODE_EMAILS", "").split(",") if e.strip()}
    if not allowed or not _test_key():
        return None
    email = _email_of(account_id)
    return _test_key() if email and email.lower() in allowed else None


def _receipt_key():
    try:
        return load_receipt_key(os.environ.get("IDENTITY_RECEIPT_KEY"))
    except ValueError:
        log.error("IDENTITY_RECEIPT_KEY is set but is not a usable EC P-256 private key")
        return None


def _latest_session(db, account_id):
    return db.execute("SELECT * FROM identity_sessions WHERE account_id=? ORDER BY created_at DESC LIMIT 1", (account_id,)).fetchone()


def _refresh(db, row):
    """Ask Stripe for the truth and persist it. Returns the (possibly updated) row."""
    if row["livemode"] == 0:
        key = _test_key()
        if key is None:
            raise stripe.error.StripeError("test mode is not configured")
        sess = stripe.identity.VerificationSession.retrieve(row["stripe_session_id"], api_key=key)
    else:
        sess = stripe.identity.VerificationSession.retrieve(row["stripe_session_id"])
    if sess.status != row["status"]:
        now = time.time()
        db.execute("UPDATE identity_sessions SET status=?, updated_at=?, verified_at=CASE WHEN ?='verified' THEN ? ELSE verified_at END WHERE id=?",
                   (sess.status, now, sess.status, now, row["id"]))
        db.commit()
        row = db.execute("SELECT * FROM identity_sessions WHERE id=?", (row["id"],)).fetchone()
    return row


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z") if ts else None


@router.get("/statement")
def statement():
    return {"statement": STATEMENT, "version": STATEMENT_VERSION, "sha256": statement_sha256(), "consentVersion": CONSENT_VERSION}


@router.get("/receipt-key")
def receipt_key():
    """The public key that verifies ID-check receipts. Pin it in the app; do not trust it from this endpoint alone."""
    key = _receipt_key()
    if key is None:
        return _err("receipt-key-not-configured", 503)
    pub, kid = receipt_public(key)
    return {"alg": "ECDSA-P256-SHA256", "kid": kid, "publicKey": pub}


@router.post("/start")
async def start(request: Request):
    account_id = actor_for(request, None).account_id
    try:
        body = await request.json()
    except ValueError:
        body = {}
    body = body if isinstance(body, dict) else {}
    if body.get("consent") is not True or body.get("consentVersion") != CONSENT_VERSION:
        return _err("consent-required", 400)
    with _db() as db:
        existing = _latest_session(db, account_id)
        if existing and existing["status"] == "verified":
            return {"sessionId": existing["stripe_session_id"], "status": "verified", "url": None}
        recent = db.execute("SELECT COUNT(*) AS n FROM identity_sessions WHERE account_id=? AND created_at>=?",
                            (account_id, time.time() - 86400)).fetchone()["n"]
        if recent >= MAX_ID_CHECKS_PER_DAY:
            return _err("too-many-id-checks", 429)
        test_key = _test_key_for(account_id)
        extra = {"api_key": test_key} if test_key else {}
        try:
            sess = stripe.identity.VerificationSession.create(
                type="document",
                options={"document": {"require_matching_selfie": True, "require_live_capture": True}},
                metadata={"account_id": str(account_id), "product": "shield_note"},
                **extra,
            )
        except stripe.error.StripeError:
            log.warning("Stripe Identity session create failed", exc_info=True)
            return _err("id-check-unavailable", 502)
        now = time.time()
        db.execute("INSERT INTO identity_sessions(id,account_id,stripe_session_id,status,livemode,consent_at,consent_version,created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (str(uuid.uuid4()), account_id, sess.id, sess.status, 0 if test_key else 1, now, CONSENT_VERSION, now))
    return {"sessionId": sess.id, "status": sess.status, "url": sess.url}


@router.get("/status")
def status(request: Request):
    account_id = actor_for(request, None).account_id
    with _db() as db:
        row = _latest_session(db, account_id)
        if not row:
            return {"status": "none", "verified": False}
        try:
            row = _refresh(db, row)
        except stripe.error.StripeError:
            return _err("id-check-unavailable", 502)
    return {"sessionId": row["stripe_session_id"], "status": row["status"], "verified": row["status"] == "verified"}


@router.post("/note")
async def note(request: Request):
    account_id = actor_for(request, None).account_id
    try:
        body = await request.json()
    except ValueError:
        body = {}
    body = body if isinstance(body, dict) else {}
    with _db() as db:
        row = _latest_session(db, account_id)
        if not row:
            return _err("no-id-check", 409)
        try:
            row = _refresh(db, row)  # never trust a stored or client-supplied status
        except stripe.error.StripeError:
            return _err("id-check-unavailable", 502)
        if row["status"] != "verified":
            return _err("id-check-not-verified", 409, status=row["status"])
        ok, reason, note_sha = verify_note(body, row["stripe_session_id"])
        if not ok:
            return _err(reason, 400)
        # Fail closed: a note without a signed receipt would be the unverifiable kind this exists to avoid.
        key = _receipt_key()
        if key is None:
            return _err("receipt-key-not-configured", 503)
        existing = db.execute("SELECT id, receipt FROM note_attestations WHERE note_sha256=?", (note_sha,)).fetchone()
        if existing:
            return {"attestationId": existing["id"], "noteSha256": note_sha, "receipt": json.loads(existing["receipt"])}
        att_id = str(uuid.uuid4())
        receipt = make_receipt(key, attestation_id=att_id, note_sha256=note_sha, device_seal_id=body["payload"]["deviceSealId"],
                               session_id=row["stripe_session_id"], test_mode=row["livemode"] == 0)
        db.execute("INSERT INTO note_attestations(id,account_id,session_id,device_seal_id,device_public_key,statement_version,note_payload,note_sha256,signature,signed_at,receipt,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (att_id, account_id, row["id"], body["payload"]["deviceSealId"], body["devicePublicKey"], STATEMENT_VERSION,
                    json.dumps(body["payload"]), note_sha, body["signature"], body["payload"]["signedAt"], json.dumps(receipt), time.time()))
    return JSONResponse({"attestationId": att_id, "noteSha256": note_sha, "receipt": receipt}, status_code=201)


@router.get("/attestations/{att_id}")
def attestation(att_id: str):
    """Public, minimal: lets a third party confirm a note exists and its ID check passed. No personal data."""
    if not UUID_RE.match(att_id):
        return _err("not-found", 404)
    with _db() as db:
        n = db.execute("SELECT * FROM note_attestations WHERE id=?", (att_id,)).fetchone()
        if not n:
            return _err("not-found", 404)
        sess = db.execute("SELECT status, livemode FROM identity_sessions WHERE id=?", (n["session_id"],)).fetchone()
    test = bool(sess) and sess["livemode"] == 0
    # A test-mode check never reads as verified to a third party: no real ID was checked.
    verified = bool(sess) and sess["status"] == "verified" and not n["revoked_at"] and not test
    out = {"attestationId": n["id"], "verified": verified, "noteSha256": n["note_sha256"],
           "deviceSealId": n["device_seal_id"], "signedAt": n["signed_at"],
           "statementVersion": n["statement_version"], "provider": "stripe-identity"}
    if test:
        out["testMode"] = True
    return out
