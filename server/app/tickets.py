"""A server-signed job ticket: proof that a chain of photos did not start before the server said so.

Flow, while the phone has signal and before its first photo for that ticket id (the job id, or "device"):
1. POST /shield/tickets {ticket_id}: the server signs a ticket (account, ticket id, its own clock, expiry) with its ticket key.
2. The phone reads its clocks, signs "shield-genesis-v1" || SHA256(ticket_hash || canonical(clock)) with its hardware key
   (plugin signGenesis), and posts everything to POST /shield/tickets/countersign. The server checks its own signature on the
   ticket, the account, the expiry and the phone's signature, then stores it. One start per account and ticket id.
3. The phone adopts the ticket hash as the `prev_hash` of its first record (plugin adoptServerTicket).

What it shows: the chain began after the server's time on the ticket and, because the server stores when it received the
countersign, no later than that. The stored phone clock is the baseline the clock check uses for the first photo.
What it does not show: who holds the phone's key, or that a photo is true. Without SHIELD_TICKET_SIGNING_KEY_PEM tickets are
closed and phones keep local tickets; nothing else changes.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .local_identity import LocalIdentity, init_once

TICKET_VERSION = 1
TTL_MS = 7 * 24 * 60 * 60 * 1000
GENESIS_CHALLENGE = b"shield-genesis-v1"
JS_SAFE_INT = 2 ** 53 - 1
FIELDS = ("version", "account_id", "ticket_id", "kid", "server_time_ms", "expires_at_ms")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class TicketsClosed(Exception):
    """The deployment has no usable ticket signing key."""


class Refused(ValueError):
    """Not accepted. The message is a stable code the phone can show."""


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def _key() -> ec.EllipticCurvePrivateKey:
    pem = os.getenv("SHIELD_TICKET_SIGNING_KEY_PEM", "")
    if not pem.strip():
        raise TicketsClosed("tickets_closed")
    try:
        key = serialization.load_pem_private_key(pem.replace("\\n", "\n").encode(), password=None)
    except (ValueError, TypeError):
        raise TicketsClosed("ticket_key_invalid") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise TicketsClosed("ticket_key_invalid")
    return key


def public_point(key=None) -> bytes:
    key = key or _key()
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def key_id() -> str:
    return hashlib.sha256(public_point()).hexdigest()[:16]


def public_info() -> dict:
    return {"kid": key_id(), "public_key_uncompressed_b64": base64.b64encode(public_point()).decode("ascii")}


def _whole(value, name):
    if type(value) is not int or value < 0 or value > JS_SAFE_INT:
        raise Refused("ticket_invalid")
    return value


def _text(value, name):
    if not isinstance(value, str) or not value or len(value) > 512:
        raise Refused("ticket_invalid")
    return value


def _validated(ticket) -> dict:
    if not isinstance(ticket, dict) or set(ticket) != set(FIELDS):
        raise Refused("ticket_invalid")
    if ticket["version"] != TICKET_VERSION or type(ticket["version"]) is not int:
        raise Refused("ticket_invalid")
    for name in ("account_id", "ticket_id", "kid"):
        _text(ticket[name], name)
    for name in ("server_time_ms", "expires_at_ms"):
        _whole(ticket[name], name)
    return ticket


def canonical(ticket: dict) -> bytes:
    return json.dumps(_validated(ticket), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def ticket_hash(ticket: dict) -> str:
    return hashlib.sha256(canonical(ticket)).hexdigest()


def normalize_clock(observation) -> dict:
    """The phone's clocks at countersign: wall and monotonic time, and which boot. Anything else is dropped, not signed."""
    if not isinstance(observation, dict):
        raise Refused("clock_invalid")
    clock = {}
    for name in ("wall_time_ms", "monotonic_ms", "boot_count"):
        if observation.get(name) is not None:
            value = observation[name]
            if type(value) is not int or abs(value) > JS_SAFE_INT or (name != "wall_time_ms" and value < 0):
                raise Refused("clock_invalid")
            clock[name] = value
    boot_id = observation.get("boot_id")
    if boot_id not in (None, ""):
        if not isinstance(boot_id, str) or len(boot_id) > 512:
            raise Refused("clock_invalid")
        clock["boot_id"] = boot_id
    if "wall_time_ms" not in clock or "monotonic_ms" not in clock or ("boot_id" not in clock and "boot_count" not in clock):
        raise Refused("clock_invalid")
    return clock


def clock_bytes(clock: dict) -> bytes:
    return json.dumps(clock, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def genesis_payload(ticket_hash_hex: str, clock: dict) -> bytes:
    if not _HEX64.fullmatch(ticket_hash_hex or ""):
        raise Refused("ticket_invalid")
    return hashlib.sha256(bytes.fromhex(ticket_hash_hex) + clock_bytes(clock)).digest()


def genesis_client_data(ticket_hash_hex: str, clock: dict) -> bytes:
    return GENESIS_CHALLENGE + genesis_payload(ticket_hash_hex, clock)


def _b64(value, code):
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise Refused(code) from None


def issue(account_id: str, ticket_id: str, now=now_ms) -> dict:
    """A signed ticket for this account and ticket id. Raises TicketsClosed when there is no key."""
    key = _key()
    t = now()
    ticket = _validated({"version": TICKET_VERSION, "account_id": account_id, "ticket_id": _text(ticket_id, "ticket_id"), "kid": key_id(),
                         "server_time_ms": t, "expires_at_ms": t + TTL_MS})
    signature = key.sign(canonical(ticket), ec.ECDSA(hashes.SHA256()))
    return {"ticket": ticket, "ticket_hash": ticket_hash(ticket), "server_signature_der_b64": base64.b64encode(signature).decode("ascii")}


@init_once
def _init(local: LocalIdentity) -> None:
    with local.db() as db:
        db.executescript("""
          CREATE TABLE IF NOT EXISTS tickets (
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES local_accounts(id),
            ticket_id TEXT NOT NULL, ticket_hash TEXT NOT NULL UNIQUE, ticket_json TEXT NOT NULL, kid TEXT NOT NULL,
            clock_json TEXT NOT NULL, public_key_b64 TEXT NOT NULL, device_signature_b64 TEXT NOT NULL,
            server_time_ms INTEGER NOT NULL, countersigned_at_ms INTEGER NOT NULL,
            UNIQUE(account_id, ticket_id)
          );
        """)


def countersign(local: LocalIdentity, account_id: str, body: dict, now=now_ms) -> dict:
    """Checks the server's own signature, the account, the expiry and the phone's signature, then stores the start."""
    _init(local)
    key = _key()
    ticket = _validated(body.get("ticket"))
    if ticket["account_id"] != account_id:
        raise Refused("ticket_for_another_account")
    if ticket["kid"] != key_id():
        raise Refused("ticket_key_unknown")
    t = now()
    if t > ticket["expires_at_ms"]:
        raise Refused("ticket_expired")
    server_signature = _b64(body.get("server_signature_der_b64"), "ticket_signature_invalid")
    try:
        key.public_key().verify(server_signature, canonical(ticket), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Refused("ticket_signature_invalid") from None
    hash_hex = ticket_hash(ticket)
    clock = normalize_clock(body.get("ticket_clock"))
    public_b64, sig_b64 = body.get("public_key_uncompressed_b64"), body.get("signature_der_b64")
    if not isinstance(public_b64, str) or not isinstance(sig_b64, str):
        raise Refused("device_signature_invalid")
    try:
        device_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _b64(public_b64, "device_signature_invalid"))
        device_key.verify(_b64(sig_b64, "device_signature_invalid"), genesis_client_data(hash_hex, clock), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise Refused("device_signature_invalid") from None
    with local.db() as db:
        same = db.execute("SELECT ticket_hash FROM tickets WHERE account_id=? AND ticket_id=?", (account_id, ticket["ticket_id"])).fetchone()
        if same:
            if same["ticket_hash"] == hash_hex:
                return {"ticket_hash": hash_hex, "started": True, "already": True}
            raise Refused("ticket_already_started")
        db.execute("INSERT INTO tickets(id,account_id,ticket_id,ticket_hash,ticket_json,kid,clock_json,public_key_b64,device_signature_b64,server_time_ms,countersigned_at_ms)"
                   " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (str(uuid.uuid4()), account_id, ticket["ticket_id"], hash_hex, canonical(ticket).decode("ascii"), ticket["kid"],
                    clock_bytes(clock).decode("ascii"), public_b64, sig_b64, ticket["server_time_ms"], t))
    return {"ticket_hash": hash_hex, "started": True, "already": False}


def _start(row) -> dict:
    return {"ticket_id": row["ticket_id"], "ticket_hash": row["ticket_hash"], "clock": json.loads(row["clock_json"]),
            "server_time_ms": row["server_time_ms"], "countersigned_at_ms": row["countersigned_at_ms"]}


def by_hash(local: LocalIdentity, account_id: str, hash_hex: str):
    """The stored start whose ticket hash this is, for this account. None when there is none."""
    return by_hashes(local, account_id, [hash_hex]).get(hash_hex)


def by_hashes(local: LocalIdentity, account_id: str, hashes) -> dict[str, dict]:
    """The same lookup for many hashes in one query: ticket hash -> start, for the ones this account has."""
    wanted = sorted({h for h in hashes if h})
    if not wanted:
        return {}
    _init(local)
    found: dict[str, dict] = {}
    with local.db() as db:
        for i in range(0, len(wanted), 500):  # stays under SQLite's limit on query parameters
            chunk = wanted[i:i + 500]
            rows = db.execute(f"SELECT * FROM tickets WHERE account_id=? AND ticket_hash IN ({','.join('?' * len(chunk))})", (account_id, *chunk)).fetchall()
            found.update({r["ticket_hash"]: _start(r) for r in rows})
    return found
