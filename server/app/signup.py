"""Sign-up by single-use invite code.

Accounts used to be made only by an administrator, and administrator access is turned off for good at launch, so after
that nobody new could ever join. An invite code lets a person make their own account without an administrator.

How it works
- An administrator (or someone with a shell on the server) mints codes before launch: POST /shield/admin/invites, or
  `python -m app.signup mint --count 5`. The code is shown once; only an HMAC of it is stored.
- POST /shield/auth/signup {email, password, invite_code} spends one code and makes a normal "capturer" account.
  Never an administrator. Signing up works after the admin lock, because it needs no administrator.
- A code works once and expires (14 days by default, 90 at most). A wrong, used or expired code all read the same.
- A code is not spent when the account cannot be made (a short password, an email that already has an account), so
  the person can fix it and try again.

Codes are 12 characters from an alphabet without look-alikes, about 60 bits, so guessing one is not practical.
They are never logged and the API never returns one except to the administrator who minted it.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import time
import uuid

from .local_identity import LocalAccount, LocalIdentity, identity

DEFAULT_DAYS = 14
MAX_DAYS = 90
MAX_BATCH = 50
GENERIC_FAILURE = "invalid_or_expired_invite"
# No 0, O, 1, I or L, so a code read aloud or from a screenshot is not misread.
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 12


def _init(local: LocalIdentity) -> None:
    with local.db() as db:
        db.executescript("""
          CREATE TABLE IF NOT EXISTS signup_invites (
            id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE,
            created_by TEXT, note TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL, expires_at REAL NOT NULL,
            used_at REAL, used_by TEXT
          );
        """)


def normalize(code: str) -> str:
    """Upper case, letters and digits only, so spaces, dashes and case do not matter."""
    return "".join(ch for ch in str(code).upper() if ch.isalnum())


def _hash(normalized: str) -> str:
    return hmac.new(LocalIdentity._secret().encode("utf-8"), f"invite:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()


def display(code: str) -> str:
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def mint(local: LocalIdentity, created_by: str | None, count: int = 1, days: int = DEFAULT_DAYS, note: str = "") -> list[str]:
    """Makes `count` codes and returns them. This is the only time the plain codes exist."""
    if not 1 <= count <= MAX_BATCH or not 1 <= days <= MAX_DAYS:
        raise ValueError("invite_request_invalid")
    _init(local)
    now = time.time()
    codes = []
    with local.db() as db:
        for _ in range(count):
            code = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
            db.execute("INSERT INTO signup_invites(id,code_hash,created_by,note,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                       (str(uuid.uuid4()), _hash(code), created_by, note[:200], now, now + days * 86400))
            codes.append(display(code))
    return codes


def create_account_with_invite(local: LocalIdentity, email: str, password: str, code: str) -> LocalAccount:
    """Spends one invite and makes a capturer account. A bad code reads the same however it is bad."""
    _init(local)
    now = time.time()
    claimed = None
    with local.db() as db:
        row = db.execute("SELECT id FROM signup_invites WHERE code_hash=? AND used_at IS NULL AND expires_at>?",
                         (_hash(normalize(code)), now)).fetchone()
        if row:
            # Atomic: of two people redeeming one code at once, only one update changes a row.
            cursor = db.execute("UPDATE signup_invites SET used_at=? WHERE id=? AND used_at IS NULL", (now, row["id"]))
            if cursor.rowcount == 1:
                claimed = row["id"]
    if not claimed:
        raise ValueError(GENERIC_FAILURE)
    try:
        account = local.create_account(email, password, "capturer")
    except ValueError:
        with local.db() as db:
            db.execute("UPDATE signup_invites SET used_at=NULL WHERE id=?", (claimed,))
        raise
    with local.db() as db:
        db.execute("UPDATE signup_invites SET used_by=? WHERE id=?", (account.id, claimed))
    return account


def main() -> None:
    parser = argparse.ArgumentParser(description="Make Shield sign-up invite codes on the server")
    parser.add_argument("action", choices=["mint"])
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--note", default="")
    args = parser.parse_args()
    try:
        codes = mint(identity(), None, args.count, args.days, args.note)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"{len(codes)} invite code(s), each works once and expires in {args.days} days. They are shown only now:")
    for code in codes:
        print(code)


if __name__ == "__main__":
    main()
