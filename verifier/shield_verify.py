#!/usr/bin/env python3
"""Independent checker for Shield photo records.

Standard library only for the hash and chain checks. The signature check also needs the `cryptography` package; without it
that check is reported as NOT CHECKED, never as passed. No network. No Shield code is imported: this file was written from
docs/RECORD_SPEC.md, so when it agrees with the server, two separate implementations of the same written rules agree.

    python shield_verify.py upload.json
    python shield_verify.py upload.json --photo original.jpg
    python shield_verify.py chain.json --photos ./originals     (files named <record_hash>.jpg)

Input is the JSON a phone sends to the server: one object, a list, {"records": [...]}, or the phone's {"packages": [{"records": [...]}]}.
Each item has `record`, `signature_der_b64`, `public_key_uncompressed_b64` and, optionally, `photo_b64`.

Exit code: 0 every check ran and passed; 2 a check failed; 3 nothing failed but the signature check could not run.

What passing shows: no signed field changed since it was signed, the file is the one that was signed, and the records link.
What it does not show: who holds the signing key, that the scene is true, or the time beyond what the phone's clock said.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path

RECORD_VERSION = 1
JS_SAFE_INT = 2 ** 53 - 1
MAX_TEXT = 512
SIGNED = (
    "version", "checkpoint_id", "photo_sha256", "ticket_id", "wall_time_ms", "monotonic_ms", "boot_id", "boot_count",
    "gnss_time_ms", "location_simulated", "sensor_hash", "depth_hash", "depth_present", "flags",
)
LINKS = {"prev_hash", "record_hash"}
REQUIRED = {"version", "checkpoint_id", "photo_sha256", "ticket_id", "wall_time_ms", "monotonic_ms", "flags"}
INTS = {"version", "wall_time_ms", "monotonic_ms", "boot_count", "gnss_time_ms", "flags"}
NON_NEGATIVE = {"version", "monotonic_ms", "boot_count", "flags"}
BOOLS = {"location_simulated", "depth_present"}
HEX = {"photo_sha256", "sensor_hash", "depth_hash"}
TEXT = {"checkpoint_id", "ticket_id", "boot_id"}


class Invalid(ValueError):
    pass


def is_hex64(v) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def canonical(record: dict) -> bytes:
    """The signed bytes: signed fields only, nulls dropped, keys sorted, ASCII, no spaces."""
    if not isinstance(record, dict):
        raise Invalid("record is not an object")
    extra = set(record) - set(SIGNED) - LINKS
    if extra:
        raise Invalid(f"field the signature would not cover: {sorted(extra)[0]}")
    if record.get("version") != RECORD_VERSION or type(record.get("version")) is not int:
        raise Invalid("version is not 1")
    for key in REQUIRED:
        if record.get(key) is None:
            raise Invalid(f"missing {key}")
    out = {}
    for key in SIGNED:
        v = record.get(key)
        if v is None:
            continue
        if key in BOOLS:
            ok = type(v) is bool
        elif key in HEX:
            ok = is_hex64(v)
        elif key in INTS:
            ok = type(v) is int and abs(v) <= JS_SAFE_INT and not (key in NON_NEGATIVE and v < 0)
        else:
            ok = isinstance(v, str) and 0 < len(v) <= MAX_TEXT
        if not ok:
            raise Invalid(f"bad value for {key}")
        out[key] = v
    present, digest = record.get("depth_present"), record.get("depth_hash")
    if (present is True and digest is None) or (digest is not None and present is not True):
        raise Invalid("depth_present and depth_hash disagree")
    return json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def signing_message(record: dict) -> bytes:
    prev = record.get("prev_hash")
    if not is_hex64(prev):
        raise Invalid("prev_hash is not 64 hex characters")
    return canonical(record) + b"|" + prev.encode("utf-8")


def signature_state(public_key_b64: str, message: bytes, signature_b64: str) -> str:
    """'ok', 'bad', or 'unavailable' when the cryptography package is not installed."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        return "unavailable"
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(public_key_b64, validate=True))
        key.verify(base64.b64decode(signature_b64, validate=True), message, ec.ECDSA(hashes.SHA256()))
        return "ok"
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return "bad"


def items_of(doc) -> list[dict]:
    if isinstance(doc, dict) and "packages" in doc:
        return [i for p in doc["packages"] for i in p.get("records", [])]
    if isinstance(doc, dict) and "records" in doc:
        return list(doc["records"])
    if isinstance(doc, dict):
        return [doc]
    if isinstance(doc, list):
        return list(doc)
    raise Invalid("input is not a record, a list of records, or a package")


def check_item(item: dict, photo: bytes | None) -> list[tuple[str, str, str]]:
    """Returns (name, 'pass'|'FAIL'|'NOT CHECKED', detail) rows for one record."""
    rows: list[tuple[str, str, str]] = []
    record = item.get("record") if isinstance(item, dict) else None
    try:
        message = signing_message(record)
    except Invalid as exc:
        return [("fields and canonical form", "FAIL", str(exc))]
    rows.append(("fields and canonical form", "pass", ""))
    expected = hashlib.sha256(message).hexdigest()
    got = record.get("record_hash")
    rows.append(("record hash matches the signed fields", "pass" if got == expected else "FAIL", "" if got == expected else "a signed field or the link changed"))

    raw = photo
    if raw is None and isinstance(item.get("photo_b64"), str):
        try:
            raw = base64.b64decode(item["photo_b64"], validate=True)
        except (binascii.Error, ValueError):
            rows.append(("photo is the one that was signed", "FAIL", "photo_b64 is not valid base64"))
            raw = None
            photo_done = True
        else:
            photo_done = False
    else:
        photo_done = False
    if raw is not None:
        same = hashlib.sha256(raw).hexdigest() == record["photo_sha256"]
        rows.append(("photo is the one that was signed", "pass" if same else "FAIL", "" if same else "file bytes differ from the signed photo_sha256 (a recompressed copy never matches)"))
    elif not photo_done:
        rows.append(("photo is the one that was signed", "NOT CHECKED", "no photo supplied"))

    sig, key = item.get("signature_der_b64"), item.get("public_key_uncompressed_b64")
    if not isinstance(sig, str) or not isinstance(key, str):
        rows.append(("device signature", "FAIL", "signature or public key missing"))
    else:
        state = signature_state(key, message, sig)
        rows.append(("device signature", {"ok": "pass", "bad": "FAIL", "unavailable": "NOT CHECKED"}[state],
                     {"ok": "", "bad": "does not verify with the key supplied", "unavailable": "install the cryptography package to check it"}[state]))
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check Shield photo records without trusting Shield.")
    ap.add_argument("file")
    ap.add_argument("--photo", help="the original file, for a single record")
    ap.add_argument("--photos", help="folder of originals named <record_hash>.jpg")
    args = ap.parse_args(argv)
    try:
        items = items_of(json.loads(Path(args.file).read_text()))
    except (OSError, ValueError, Invalid) as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 2
    if args.photo and len(items) != 1:
        print("--photo needs exactly one record; use --photos for several", file=sys.stderr)
        return 2
    failed = unchecked_signature = False
    previous = None
    for n, item in enumerate(items, 1):
        record = item.get("record") if isinstance(item, dict) else None
        rh = record.get("record_hash") if isinstance(record, dict) else None
        photo = None
        if args.photo:
            photo = Path(args.photo).read_bytes()
        elif args.photos and is_hex64(rh) and (Path(args.photos) / f"{rh}.jpg").is_file():
            photo = (Path(args.photos) / f"{rh}.jpg").read_bytes()
        print(f"record {n}: {rh or 'no record_hash'}")
        rows = check_item(item, photo)
        if previous is not None and isinstance(record, dict):
            linked = record.get("prev_hash") == previous
            rows.append(("links to the record before it", "pass" if linked else "FAIL", "" if linked else "prev_hash is not the previous record_hash"))
        for name, state, detail in rows:
            print(f"  {state:<11} {name}{(' — ' + detail) if detail else ''}")
            failed |= state == "FAIL"
            unchecked_signature |= name == "device signature" and state == "NOT CHECKED"
        previous = rh
    if items and isinstance(items[0].get("record"), dict):
        first = items[0]["record"]
        print(f"first record starts at its ticket: {'yes' if first.get('prev_hash') == first.get('ticket_id') else 'no (informational)'}")
    print("RESULT:", "FAILED" if failed else ("PASSED, SIGNATURE NOT CHECKED" if unchecked_signature else "PASSED"))
    print("This shows nothing changed since signing. It does not show who holds the key, that the scene is true, or the time beyond the phone's clock.")
    return 2 if failed else (3 if unchecked_signature else 0)


if __name__ == "__main__":
    sys.exit(main())
