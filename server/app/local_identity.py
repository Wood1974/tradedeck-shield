"""Shield-owned accounts and job grants for independent deployments.

Accounts are provisioned by an administrator; there is no public self-signup.
The SQLite database must live on a persistent disk and be backed up with evidence.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass

import jwt

ISSUER = "tradedeck-shield-local"
AUDIENCE = "shield"
TOKEN_TTL_SECONDS = 12 * 60 * 60


@dataclass(frozen=True)
class LocalAccount:
    id: str
    email: str
    role: str


class LocalIdentity:
    def __init__(self, database_url: str):
        if not database_url.startswith("sqlite:///"):
            raise ValueError("local_identity_requires_sqlite_database")
        self.path = database_url.removeprefix("sqlite:///")
        self._init()

    def db(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _init(self):
        with self.db() as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS local_accounts (
                id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin','capturer')),
                active INTEGER NOT NULL DEFAULT 1,
                auth_version INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
              );
              CREATE TABLE IF NOT EXISTS local_job_grants (
                account_id TEXT NOT NULL REFERENCES local_accounts(id),
                job_id TEXT NOT NULL, point_id TEXT NOT NULL,
                granted_by TEXT NOT NULL REFERENCES local_accounts(id),
                created_at REAL NOT NULL,
                PRIMARY KEY(account_id,job_id,point_id)
              );
            """)

    @staticmethod
    def _digest(password: str, salt: bytes) -> str:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1).hex()

    def create_account(self, email: str, password: str, role: str = "capturer") -> LocalAccount:
        email = email.strip().lower()
        if not email or "@" not in email or len(email) > 254:
            raise ValueError("invalid_email")
        if len(password) < 12 or len(password) > 1024:
            raise ValueError("password_length_invalid")
        if role not in {"admin", "capturer"}:
            raise ValueError("invalid_role")
        salt = secrets.token_bytes(16)
        account = LocalAccount(str(uuid.uuid4()), email, role)
        try:
            with self.db() as db:
                db.execute("INSERT INTO local_accounts(id,email,password_salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?)",
                           (account.id,email,salt.hex(),self._digest(password,salt),role,time.time()))
        except sqlite3.IntegrityError as exc:
            raise ValueError("account_already_exists") from exc
        return account

    def authenticate(self, email: str, password: str) -> LocalAccount | None:
        with self.db() as db:
            row = db.execute("SELECT * FROM local_accounts WHERE email=?", (email.strip().lower(),)).fetchone()
        # Perform the same expensive hash even for unknown accounts.
        salt = bytes.fromhex(row["password_salt"]) if row else b"\0" * 16
        expected = row["password_hash"] if row else "0" * 64
        valid = hmac.compare_digest(self._digest(password, salt), expected)
        if not row or not valid or not row["active"]:
            return None
        return LocalAccount(row["id"], row["email"], row["role"])

    @staticmethod
    def _secret() -> str:
        secret = os.getenv("SHIELD_LOCAL_JWT_SECRET", "")
        if len(secret.encode("utf-8")) < 32:
            raise RuntimeError("local_jwt_secret_not_configured")
        return secret

    def token(self, account: LocalAccount) -> str:
        with self.db() as db:
            row = db.execute("SELECT auth_version,active FROM local_accounts WHERE id=?", (account.id,)).fetchone()
        if not row or not row["active"]:
            raise ValueError("account_inactive")
        now = int(time.time())
        return jwt.encode({"sub":account.id,"iss":ISSUER,"aud":AUDIENCE,"iat":now,
                           "exp":now+TOKEN_TTL_SECONDS,"ver":row["auth_version"]},
                          self._secret(),algorithm="HS256")

    def verify(self, token: str) -> LocalAccount:
        claims = jwt.decode(token,self._secret(),algorithms=["HS256"],issuer=ISSUER,audience=AUDIENCE,
                            options={"require":["sub","iss","aud","iat","exp","ver"]})
        with self.db() as db:
            row = db.execute("SELECT id,email,role,active,auth_version FROM local_accounts WHERE id=?",
                             (claims["sub"],)).fetchone()
        if not row or not row["active"] or claims["ver"] != row["auth_version"]:
            raise ValueError("account_inactive_or_revoked")
        return LocalAccount(row["id"],row["email"],row["role"])

    def grant(self, actor: LocalAccount, account_id: str, job_id: str, point_id: str):
        if actor.role != "admin":
            raise PermissionError("admin_required")
        if not job_id.strip() or not point_id.strip() or len(job_id)>200 or len(point_id)>200:
            raise ValueError("invalid_job_or_point")
        with self.db() as db:
            target = db.execute("SELECT active FROM local_accounts WHERE id=?",(account_id,)).fetchone()
            if not target or not target["active"]:
                raise ValueError("account_not_found")
            db.execute("INSERT OR IGNORE INTO local_job_grants VALUES(?,?,?,?,?)",
                       (account_id,job_id,point_id,actor.id,time.time()))

    def allowed(self, account_id: str, job_id: str, point_id: str) -> bool:
        with self.db() as db:
            return db.execute("""SELECT 1 FROM local_job_grants g JOIN local_accounts a ON a.id=g.account_id
                                 WHERE g.account_id=? AND g.job_id=? AND g.point_id=? AND a.active=1""",
                              (account_id,job_id,point_id)).fetchone() is not None

    def revoke(self, actor: LocalAccount, account_id: str, job_id: str, point_id: str):
        if actor.role != "admin":
            raise PermissionError("admin_required")
        with self.db() as db:
            db.execute("DELETE FROM local_job_grants WHERE account_id=? AND job_id=? AND point_id=?",
                       (account_id,job_id,point_id))

    def grants_for(self, account_id: str) -> list[dict[str,str]]:
        with self.db() as db:
            rows = db.execute("SELECT job_id,point_id FROM local_job_grants WHERE account_id=? ORDER BY job_id,point_id",
                              (account_id,)).fetchall()
        return [dict(row) for row in rows]

    def deactivate(self, actor: LocalAccount, account_id: str):
        if actor.role != "admin":
            raise PermissionError("admin_required")
        if actor.id == account_id:
            raise ValueError("cannot_deactivate_self")
        with self.db() as db:
            changed = db.execute("UPDATE local_accounts SET active=0,auth_version=auth_version+1 WHERE id=?",
                                 (account_id,)).rowcount
        if not changed:
            raise ValueError("account_not_found")

    def reset_password(self, account_id: str, password: str):
        if len(password) < 12 or len(password) > 1024:
            raise ValueError("password_length_invalid")
        salt = secrets.token_bytes(16)
        with self.db() as db:
            changed = db.execute("""UPDATE local_accounts SET password_salt=?,password_hash=?,auth_version=auth_version+1
                                     WHERE id=? AND active=1""",
                                 (salt.hex(),self._digest(password,salt),account_id)).rowcount
        if not changed:
            raise ValueError("account_not_found")


def identity() -> LocalIdentity:
    return LocalIdentity(os.getenv("SHIELD_DATABASE_URL","sqlite:///./shield.db"))


def main():
    parser = argparse.ArgumentParser(description="Provision the first Shield administrator on the server")
    parser.add_argument("action", choices=["create-admin","reset-password"])
    parser.add_argument("--email",required=True)
    args = parser.parse_args()
    password = getpass.getpass("New Shield administrator password (12+ characters): ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        parser.error("passwords do not match")
    local = identity()
    if args.action == "create-admin":
        account = local.create_account(args.email,password,"admin")
        print("Created Shield administrator:",account.id)
    else:
        with local.db() as db:
            row = db.execute("SELECT id FROM local_accounts WHERE email=?",(args.email.strip().lower(),)).fetchone()
        if not row: parser.error("account not found")
        local.reset_password(row["id"],password)
        print("Password reset; existing tokens revoked")


if __name__ == "__main__":
    main()
