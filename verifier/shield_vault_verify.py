#!/usr/bin/env python3
"""Independent checker for what the Shield phone app exports: a photo bundle (.shield.json) or a close-out packet (.shield-record.json).

Written from the format described in docs/features/vault-verifier.md, not from the app's code. Standard library only for the
hash, chain and counting checks. The signature checks also need the `cryptography` package; without it they are reported as
NOT CHECKED, never as passed. No network. Shield's own code is not imported.

    python shield_vault_verify.py photo.shield.json
    python shield_vault_verify.py closeout.shield-record.json --signer 1A2B3C4D·5E6F7A8B

Exit code: 0 every check ran and passed; 2 a check failed; 3 nothing failed but a signature check could not run.

What passing shows: nothing signed changed since the phone signed it, the photo is the one that was signed, the records link, and (for a
packet) the counts and times are consistent. What it does not show: who holds the signing key (pass --signer with a seal ID you got from the
photographer another way to pin it), that the scene is true, or the time beyond what the phone's clock said. A packet's photographer note
and ID-check receipt are NOT checked here (they need the service's receipt keys); the app's Verify tab checks them.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
import time
from datetime import datetime
from decimal import Decimal
from pathlib import Path

CLOCK_SKEW_S = 5 * 60
MAX_BYTES = 10 * 1024 * 1024
ZERO_BYTES = "0" * 64


class Unreadable(ValueError):
    pass


# --- the canonical form: JSON with sorted keys, no spaces, numbers written the way JavaScript writes them ---

def js_number(x) -> str:
    """A number as JavaScript's JSON.stringify writes it (Python's repr differs for very small and very large values)."""
    if isinstance(x, bool):
        raise Unreadable("bool is not a number")
    if isinstance(x, int):
        return str(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise Unreadable("non-finite number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    _, digit_tuple, exponent = Decimal(repr(abs(x))).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0") or "0"
    exponent += len("".join(map(str, digit_tuple))) - len(digits)  # trailing zeros moved into the exponent
    k, n = len(digits), exponent + len(digits)  # value = 0.<digits> x 10^n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + body


def canonical(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return js_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(value[k]) for k in sorted(value)) + "}"
    raise Unreadable(f"unsupported value {type(value).__name__}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal_id(public_key_b64: str) -> str:
    h = sha256_hex(base64.b64decode(public_key_b64, validate=True))
    return f"{h[:8]}·{h[8:16]}".upper()


def signature_state(public_key_b64: str, payload, signature_b64: str) -> str:
    """'ok', 'bad', or 'unavailable' when the cryptography package is not installed. The phone signs with ECDSA P-256 over SHA-256 and writes r||s."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError:
        return "unavailable"
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(public_key_b64, validate=True))
        raw = base64.b64decode(signature_b64, validate=True)
        if len(raw) != 64:
            return "bad"
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        key.verify(der, canonical(payload).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return "ok"
    except (InvalidSignature, ValueError, TypeError, binascii.Error, Unreadable):
        return "bad"


Row = tuple[str, str, str]  # name, state ("pass" / "FAIL" / "NOT CHECKED" / "info"), detail


def row(name: str, ok: bool, detail: str = "") -> Row:
    return (name, "pass" if ok else "FAIL", "" if ok else detail)


def sig_row(name: str, state: str) -> Row:
    return (name, {"ok": "pass", "bad": "FAIL", "unavailable": "NOT CHECKED"}[state], {"bad": "does not verify", "unavailable": "install the cryptography package"}.get(state, ""))


def record_rows(record: dict, public_key_b64: str, label: str = "") -> list[Row]:
    """The checks for one sealed record against the key that signed it."""
    p = f"{label}: " if label else ""
    rows: list[Row] = []
    try:
        rows.append(row(p + "seal ID belongs to the key", record.get("deviceSealId") == seal_id(public_key_b64), "deviceSealId is not derived from this key"))
        unsigned = {k: v for k, v in record.items() if k not in ("chainHead", "signature")}
        record_hash = sha256_hex(canonical(unsigned).encode("utf-8"))
        want = sha256_hex((str(record.get("prevChain")) + "|" + record_hash).encode("utf-8"))
        rows.append(row(p + "chain head recomputes", record.get("chainHead") == want, "chainHead is not SHA-256(prevChain|record hash)"))
        rows.append(sig_row(p + "record signature", signature_state(public_key_b64, {**unsigned, "chainHead": record.get("chainHead")}, str(record.get("signature")))))
    except (Unreadable, ValueError, TypeError, binascii.Error) as exc:
        rows.append((p + "record readable", "FAIL", str(exc)))
    rows.append(row(p + "capture kind is native-camera", record.get("captureKind") == "native-camera", f"captureKind is {record.get('captureKind')!r}"))
    return rows


def bundle_rows(doc: dict) -> list[Row]:
    record, key = doc.get("record"), doc.get("devicePublicKey")
    if not isinstance(record, dict) or not isinstance(doc.get("originalB64"), str):
        raise Unreadable("not a photo bundle (needs record and originalB64)")
    rows: list[Row] = []
    try:
        photo = base64.b64decode(doc["originalB64"], validate=True)
        rows.append(row("photo bytes match the signed hash", sha256_hex(photo) == record.get("sha256"), "the photo is not the one that was signed"))
        rows.append(("photo size matches the record", "pass" if len(photo) == record.get("bytes") else "info", "" if len(photo) == record.get("bytes") else f"record says {record.get('bytes')} bytes, file is {len(photo)}"))
    except (binascii.Error, ValueError):
        rows.append(("photo bytes readable", "FAIL", "originalB64 is not valid base64"))
    if not isinstance(key, str):
        rows.append(("signing key present", "FAIL", "no devicePublicKey, so the record cannot be authenticated"))
    else:
        rows += record_rows(record, key)
        rows.append(("signer", "info", f"seal ID {seal_id(key)}"))
    att = (record.get("attest") or {}).get("kind")
    rows.append(("device attestation", "info", "none claimed" if att == "none" else f"{att} claimed; the token is not in the export, so this tool cannot check it"))
    return rows


def packet_rows(doc: dict, expected_signer: str | None, now: float) -> list[Row]:
    integrity = doc.get("integrity")
    body = {k: v for k, v in doc.items() if k != "integrity"}
    key = body.get("devicePublicKey")
    if not isinstance(integrity, dict) or not isinstance(key, str) or not isinstance(body.get("points"), list):
        raise Unreadable("not a close-out packet (needs integrity, devicePublicKey and points)")
    rows: list[Row] = [row("packet hash recomputes", sha256_hex(canonical(body).encode("utf-8")) == integrity.get("hash"), "the packet was changed after it was signed"),
                       sig_row("packet signature", signature_state(key, body, str(integrity.get("signature"))))]
    signer = seal_id(key)
    rows.append(row("seal ID belongs to the key", body.get("deviceSealId") == signer, "deviceSealId is not derived from the packet's key"))
    rows.append(("signer", "pass" if expected_signer and expected_signer.upper() == signer else ("FAIL" if expected_signer else "info"),
                 f"seal ID {signer}" + ("" if expected_signer and expected_signer.upper() == signer else (f", expected {expected_signer}" if expected_signer else "; not pinned (pass --signer with an ID you got from the photographer another way)"))))
    records = []
    for point in body["points"]:
        r = point.get("record")
        if not r:
            continue
        records.append(r)
        rows += record_rows(r, key, point.get("id", "?"))
        rows.append(row(f"{point.get('id')}: record belongs to this job", r.get("jobId") == (body.get("job") or {}).get("id"), "jobId differs from the packet's job"))
        rows.append(row(f"{point.get('id')}: record belongs to this point", r.get("checkpointId") == point.get("id"), "checkpointId differs from the point"))
    ph = body.get("photographer")
    if ph:
        rows.append(("photographer note and ID receipt", "NOT CHECKED", "needs the service's receipt keys; check in the app's Verify tab"))
    elif any("attestationId" in r for r in records):
        rows.append(("photographer note present", "FAIL", "photos were signed as belonging to a note, but the packet carries none"))
    rows.append(row("no duplicate records", len({r.get("id") for r in records}) == len(records), "the same record appears twice"))
    rows.append(row("no forked chain", len({r.get("prevChain") for r in records}) == len(records), "two records share the same previous link"))
    by_head = {r.get("chainHead"): r for r in records}
    order_ok = all(not (by_head.get(r.get("prevChain")) and by_head[r["prevChain"]].get("createdAt", "") > r.get("createdAt", "")) for r in records)
    rows.append(row("chain is in time order", order_ok, "a record is dated before the one it follows"))
    try:
        closed = datetime.fromisoformat(str(body.get("closedAt")).replace("Z", "+00:00")).timestamp()
        shot = [datetime.fromisoformat(str(r.get("createdAt")).replace("Z", "+00:00")).timestamp() for r in records]
        rows.append(row("closed after every photo", all(closed >= t for t in shot), "closedAt is before a photo's time"))
        rows.append(row("no time in the future", max([closed, *shot]) <= now + CLOCK_SKEW_S, "a time is more than five minutes ahead of this computer's clock"))
    except ValueError:
        rows.append(("times readable", "FAIL", "a time is not a valid date"))
    pts = body["points"]
    rows.append(row("counts add up", body.get("counts") == {"points": len(pts), "sealed": sum(1 for p in pts if p.get("record")), "missing": sum(1 for p in pts if not p.get("record"))}, "counts do not match the points"))
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check what the Shield app exports without trusting Shield.")
    ap.add_argument("file")
    ap.add_argument("--signer", help="the photographer's seal ID, obtained another way, to pin the signing key")
    args = ap.parse_args(argv)
    try:
        path = Path(args.file)
        if path.stat().st_size > MAX_BYTES:
            raise Unreadable("file is larger than 10 MB")
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise Unreadable("not a JSON object")
        if "originalB64" in doc:
            kind, rows = "photo bundle", bundle_rows(doc)
        elif "integrity" in doc:
            kind, rows = "close-out packet", packet_rows(doc, args.signer, time.time())
        else:
            raise Unreadable("neither a photo bundle nor a close-out packet")
    except (OSError, ValueError) as exc:  # Unreadable is a ValueError
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 2
    print(f"{kind}: {args.file}")
    for name, state, detail in rows:
        print(f"  {state:<11} {name}{(' — ' + detail) if detail else ''}")
    failed = any(s == "FAIL" for _, s, _ in rows)
    unchecked = any(s == "NOT CHECKED" and "signature" in n for n, s, _ in rows)
    print("RESULT:", "FAILED" if failed else ("PASSED, SIGNATURE NOT CHECKED" if unchecked else "PASSED"))
    print("This shows nothing changed since signing. It does not show who holds the key, that the scene is true, or the time beyond the phone's clock.")
    return 2 if failed else (3 if unchecked else 0)


if __name__ == "__main__":
    sys.exit(main())
