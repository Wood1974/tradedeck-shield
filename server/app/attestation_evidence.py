"""Apple's own evidence for a phone key, kept so someone other than this server can check it.

The server already verifies Apple's attestation when a phone enrolls and Apple's assertion when a photo arrives, but used to keep only
its verdict. A verdict can only be taken on trust. This keeps what Apple actually signed: the attestation object (its certificate chain
is inside it) with the challenge it was made over, and, per photo, the assertion (stored on the capture row by captures.ingest).

With these, verifier/shield_apple_verify.py re-does Apple's checks offline against Apple's published root, without this server.

Keys enrolled before this existed have no stored attestation object. They stay usable; their evidence reads as not kept.
"""
from __future__ import annotations

import time


def _init(store) -> None:
    with store.db() as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS attestation_evidence("
            "key_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, attestation_b64 TEXT NOT NULL, challenge TEXT NOT NULL, "
            "app_id TEXT NOT NULL, environment TEXT NOT NULL, created_at REAL NOT NULL)"
        )


def save(store, key_id: str, account_id: str, attestation_b64: str, challenge: str, app_id: str, environment: str) -> None:
    """Keep the attestation a key was enrolled with. The first one kept for a key stays: a key enrols once."""
    _init(store)
    with store.db() as c:
        c.execute(
            "INSERT OR IGNORE INTO attestation_evidence(key_id,account_id,attestation_b64,challenge,app_id,environment,created_at) VALUES(?,?,?,?,?,?,?)",
            (key_id, account_id, attestation_b64, challenge, app_id, environment, time.time()),
        )


def get(store, key_id: str, account_id: str) -> dict | None:
    """The kept attestation for this account's key, or None (never enrolled with it kept, or another account's key)."""
    _init(store)
    with store.db() as c:
        row = c.execute("SELECT * FROM attestation_evidence WHERE key_id=? AND account_id=?", (key_id, account_id)).fetchone()
    if not row:
        return None
    return {"key_id": row["key_id"], "attestation_b64": row["attestation_b64"], "challenge": row["challenge"],
            "app_id": row["app_id"], "environment": row["environment"]}
