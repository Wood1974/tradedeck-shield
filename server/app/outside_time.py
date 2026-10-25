"""An outside time-stamp for each account's chain heads, taken once a day.

A chain head is a stored record that no later record links to. Its record hash already commits to every record before it, so one
time-stamp on the head says all of them existed by then. Only a hash leaves the server (see rfc3161.chain_head_imprint). It is
off unless SHIELD_TSA_ENABLED=true, and it never blocks or delays an upload: a failed call is logged and tried again on the next
run. SHIELD_TSA_URL defaults to DigiCert's public time-stamp service. Chain checking of the TSA certificate needs
SHIELD_TSA_CA_PEM_PATH (a file of trusted roots); without it a token is kept as `chain_checked: false` and says so.

What a stamp shows: a time-stamp authority says the chain, up to that head, existed by its time. It does not show who made a
photo, that the scene is true, or when it was taken (only an upper bound), and it is only as good as the authority and the roots
you trust. A record stored after the last run reads `waiting`.
"""
from __future__ import annotations

import base64
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone

import httpx

from . import rfc3161
from .local_identity import LocalIdentity, init_once

log = logging.getLogger(__name__)
DAY_S = 86_400
DEFAULT_URL = "http://timestamp.digicert.com"


def enabled() -> bool:
    return os.getenv("SHIELD_TSA_ENABLED", "false").lower() == "true"


def tsa_url() -> str:
    return os.getenv("SHIELD_TSA_URL", DEFAULT_URL)


def _roots():
    path = os.getenv("SHIELD_TSA_CA_PEM_PATH")
    if not path:
        return []
    with open(path, "rb") as f:
        return rfc3161.load_roots(f.read())


@init_once
def _init(local: LocalIdentity) -> None:
    with local.db() as db:
        db.executescript("""
          CREATE TABLE IF NOT EXISTS outside_timestamps (
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES local_accounts(id),
            head_record_hash TEXT NOT NULL, imprint_hex TEXT NOT NULL, reply_b64 TEXT NOT NULL,
            gen_time REAL NOT NULL, tsa_url TEXT NOT NULL, chain_checked INTEGER NOT NULL, created_at REAL NOT NULL,
            UNIQUE(account_id, head_record_hash)
          );
          CREATE TABLE IF NOT EXISTS outside_timestamp_runs (id INTEGER PRIMARY KEY CHECK (id = 1), last_run REAL NOT NULL);
        """)


def _post(url: str, request: bytes) -> bytes:
    r = httpx.post(url, content=request, headers={"Content-Type": "application/timestamp-query"}, timeout=20, follow_redirects=False)
    if r.status_code != 200:
        raise RuntimeError(f"tsa_http_{r.status_code}")
    return r.content


def pending_heads(local: LocalIdentity) -> list[tuple[str, str]]:
    _init(local)
    with local.db() as db:
        rows = db.execute("""
          SELECT c.account_id, c.record_hash FROM captures c
           WHERE NOT EXISTS (SELECT 1 FROM captures n WHERE n.account_id = c.account_id AND n.prev_hash = c.record_hash)
             AND NOT EXISTS (SELECT 1 FROM outside_timestamps t WHERE t.account_id = c.account_id AND t.head_record_hash = c.record_hash)
        """).fetchall()
    return [(r["account_id"], r["record_hash"]) for r in rows]


def stamp_pending(local: LocalIdentity, post=_post, roots=None, url: str | None = None, now=time.time) -> dict:
    """One pass. Never raises: a head that cannot be stamped is logged and left for the next pass."""
    url = url or tsa_url()
    roots = _roots() if roots is None else roots
    done = failed = 0
    for account_id, head in pending_heads(local):
        try:
            imprint, nonce = rfc3161.chain_head_imprint(head), rfc3161.new_nonce()
            reply = post(url, rfc3161.build_request(imprint, nonce))
            checked = rfc3161.check_reply(reply, imprint, nonce, roots)
            with local.db() as db:
                db.execute("INSERT OR IGNORE INTO outside_timestamps(id,account_id,head_record_hash,imprint_hex,reply_b64,gen_time,tsa_url,chain_checked,created_at)"
                           " VALUES(?,?,?,?,?,?,?,?,?)",
                           (str(uuid.uuid4()), account_id, head, imprint.hex(), base64.b64encode(reply).decode("ascii"),
                            checked["gen_time"].timestamp(), url, int(checked["chain_checked"]), now()))
            done += 1
        except Exception as exc:  # network, a refusal, or a reply that failed its checks: nothing is kept
            failed += 1
            log.warning("Outside time-stamp for a chain head was not taken (%s: %s)", type(exc).__name__, str(exc)[:120])
    return {"stamped": done, "failed": failed}


def run_if_due(local: LocalIdentity, post=_post, roots=None, now=time.time) -> dict | None:
    """Runs a pass when the last one was at least a day ago. The time of the last run survives a restart."""
    _init(local)
    t = now()
    with local.db() as db:
        row = db.execute("SELECT last_run FROM outside_timestamp_runs WHERE id = 1").fetchone()
        if row and t - row["last_run"] < DAY_S:
            return None
        db.execute("INSERT INTO outside_timestamp_runs(id,last_run) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last_run = excluded.last_run", (t,))
    return stamp_pending(local, post=post, roots=roots, now=now)


def start_daily(local: LocalIdentity) -> threading.Thread:
    def loop():
        time.sleep(60)
        while True:
            try:
                run_if_due(local)
            except Exception:
                log.exception("Outside time-stamp run failed")
            time.sleep(3600)
    thread = threading.Thread(target=loop, name="outside-time", daemon=True)
    thread.start()
    return thread


def coverage(local: LocalIdentity, account_id: str) -> dict[str, dict]:
    """record_hash -> the earliest stamp that covers it (the stamped head, or any later record in its chain's past)."""
    _init(local)
    with local.db() as db:
        stamps = db.execute("SELECT head_record_hash, gen_time, tsa_url, chain_checked FROM outside_timestamps WHERE account_id=? ORDER BY gen_time", (account_id,)).fetchall()
        if not stamps:
            return {}
        prev = {r["record_hash"]: r["prev_hash"] for r in db.execute("SELECT record_hash, prev_hash FROM captures WHERE account_id=?", (account_id,)).fetchall()}
    out: dict[str, dict] = {}
    for s in stamps:  # oldest stamp first, so a record keeps the earliest time that covers it
        h, hops = s["head_record_hash"], 0
        while h in prev and hops < 100_000:
            if h in out:
                break  # an earlier stamp already covered this record and everything before it, so the rest of the walk finds nothing new
            out[h] = {"gen_time": s["gen_time"], "tsa_url": s["tsa_url"], "chain_checked": bool(s["chain_checked"]), "head_record_hash": s["head_record_hash"]}
            h, hops = prev[h], hops + 1
    return out


def view(cover: dict | None) -> dict:
    if cover:
        return {"status": "stamped", "gen_time": datetime.fromtimestamp(cover["gen_time"], timezone.utc).isoformat(), "tsa": cover["tsa_url"], "chain_checked": cover["chain_checked"]}
    return {"status": "waiting" if enabled() else "off"}


def token_for(local: LocalIdentity, account_id: str, record_hash: str) -> dict | None:
    """The stored reply that covers this record, for the account that owns it. None when there is none."""
    cover = coverage(local, account_id).get(record_hash)
    if not cover:
        return None
    with local.db() as db:
        row = db.execute("SELECT * FROM outside_timestamps WHERE account_id=? AND head_record_hash=?", (account_id, cover["head_record_hash"])).fetchone()
    return {"head_record_hash": row["head_record_hash"], "imprint_sha256": row["imprint_hex"], "reply_der_b64": row["reply_b64"],
            "gen_time": datetime.fromtimestamp(row["gen_time"], timezone.utc).isoformat(), "tsa": row["tsa_url"], "chain_checked": bool(row["chain_checked"])}
