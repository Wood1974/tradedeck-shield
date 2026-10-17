"""Forgot-password by an emailed one-time code.

Shield accounts are made by an administrator and there is no self sign-up, so a forgotten password needs a way back
that does not depend on an administrator (admin access is turned off for good at launch).

How it works
- POST /shield/auth/forgot {email} always answers the same way, whether or not the email has an account, so it cannot
  be used to find accounts. If there is an active account, an 8-digit code is emailed to it.
- Only an HMAC of the code is stored, one live code per account, valid for 15 minutes, with 5 tries.
- POST /shield/auth/reset {email, code, new_password} spends the code, sets the new password and revokes every
  sign-in (LocalIdentity.reset_password bumps auth_version).
- Requests are limited to 3 per account per hour, on top of the global per-IP limiter.

The code is never logged and is never returned by the API.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time

import requests

from .local_identity import LocalIdentity

log = logging.getLogger(__name__)

CODE_TTL_SECONDS = 15 * 60
MAX_ATTEMPTS = 5
MAX_REQUESTS_PER_HOUR = 3
RESEND_URL = "https://api.resend.com/emails"
GENERIC_FAILURE = "invalid_or_expired_code"


class MailNotConfigured(RuntimeError):
    """No email service is set up on this server, so no code can be sent."""


def mail_configured() -> bool:
    return bool(os.getenv("RESEND_API_KEY", "").strip() and os.getenv("SHIELD_MAIL_FROM", "").strip())


def send_email(to: str, subject: str, text: str) -> None:
    """Sends one email through Resend. Replaced in tests, so tests send nothing."""
    if not mail_configured():
        raise MailNotConfigured("email_not_configured")
    response = requests.post(
        RESEND_URL,
        headers={"Authorization": "Bearer " + os.environ["RESEND_API_KEY"].strip()},
        json={"from": os.environ["SHIELD_MAIL_FROM"].strip(), "to": [to], "subject": subject, "text": text},
        timeout=10,
    )
    if response.status_code >= 300:
        # The body can say why (an unverified sender, say). It never contains the code, so it is safe to log.
        raise RuntimeError(f"mail_send_failed:{response.status_code}:{response.text[:200]}")


def _init(local: LocalIdentity) -> None:
    with local.db() as db:
        db.executescript("""
          CREATE TABLE IF NOT EXISTS password_resets (
            account_id TEXT PRIMARY KEY REFERENCES local_accounts(id),
            code_hash TEXT NOT NULL, expires_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL
          );
          CREATE TABLE IF NOT EXISTS password_reset_requests (
            account_id TEXT NOT NULL, requested_at REAL NOT NULL
          );
        """)


def _hash(account_id: str, code: str) -> str:
    return hmac.new(LocalIdentity._secret().encode("utf-8"), f"{account_id}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()


def _account(local: LocalIdentity, email: str):
    with local.db() as db:
        return db.execute("SELECT id,email,role,active FROM local_accounts WHERE email=?", (email.strip().lower(),)).fetchone()


def request_code(local: LocalIdentity, email: str) -> bool:
    """Emails a code if the email belongs to an active account. Returns whether one was sent.

    The caller must answer the same way either way. Raises MailNotConfigured before doing anything else when no
    email service is set up, which says nothing about any account."""
    if not mail_configured():
        raise MailNotConfigured("email_not_configured")
    _init(local)
    row = _account(local, email)
    if not row or not row["active"]:
        return False
    # Once administrator access has been turned off an administrator cannot be reset (see the admin launch lock).
    if row["role"] == "admin" and getattr(local, "is_locked", lambda: False)():
        return False
    now = time.time()
    with local.db() as db:
        recent = db.execute("SELECT COUNT(*) FROM password_reset_requests WHERE account_id=? AND requested_at>?",
                            (row["id"], now - 3600)).fetchone()[0]
        if recent >= MAX_REQUESTS_PER_HOUR:
            return False
        code = f"{secrets.randbelow(10 ** 8):08d}"
        db.execute("INSERT OR REPLACE INTO password_resets(account_id,code_hash,expires_at,attempts,created_at) VALUES(?,?,?,0,?)",
                   (row["id"], _hash(row["id"], code), now + CODE_TTL_SECONDS, now))
        db.execute("INSERT INTO password_reset_requests(account_id,requested_at) VALUES(?,?)", (row["id"], now))
    try:
        send_email(
            row["email"],
            "Your Shield password reset code",
            f"Your Shield password reset code is {code}\n\nIt expires in 15 minutes and works once.\n\n"
            "If you did not ask for this, ignore this email. Your password has not changed.\n",
        )
    except Exception as exc:  # the caller still answers generically; the reason goes to the server log only
        log.error("password reset email was not sent: %s", exc)
        return False
    return True


def confirm_reset(local: LocalIdentity, email: str, code: str, new_password: str) -> None:
    """Spends the code and sets the new password. Every failure about the code reads the same."""
    if len(new_password) < 12 or len(new_password) > 1024:
        raise ValueError("password_length_invalid")  # checked first, so a typo does not burn a try
    _init(local)
    row = _account(local, email)
    reset = None
    if row and row["active"]:
        with local.db() as db:
            reset = db.execute("SELECT * FROM password_resets WHERE account_id=?", (row["id"],)).fetchone()
    code = "".join(ch for ch in code if ch.isdigit())
    # The same work happens whether or not there is a code to check.
    expected = reset["code_hash"] if reset else "0" * 64
    owner = row["id"] if row else ""
    good = hmac.compare_digest(_hash(owner, code), expected)
    now = time.time()
    if not reset or reset["expires_at"] < now or reset["attempts"] >= MAX_ATTEMPTS:
        if reset:
            with local.db() as db:
                db.execute("DELETE FROM password_resets WHERE account_id=?", (row["id"],))
        raise ValueError(GENERIC_FAILURE)
    if not good:
        with local.db() as db:
            attempts = reset["attempts"] + 1
            if attempts >= MAX_ATTEMPTS:
                db.execute("DELETE FROM password_resets WHERE account_id=?", (row["id"],))
            else:
                db.execute("UPDATE password_resets SET attempts=? WHERE account_id=?", (attempts, row["id"]))
        raise ValueError(GENERIC_FAILURE)
    local.reset_password(row["id"], new_password)  # revokes every existing sign-in
    with local.db() as db:
        db.execute("DELETE FROM password_resets WHERE account_id=?", (row["id"],))
