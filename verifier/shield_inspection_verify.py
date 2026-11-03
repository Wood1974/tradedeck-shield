#!/usr/bin/env python3
"""Check an inspection report's AI section and human approval without the Shield server. Standard library plus `cryptography`.

    python shield_inspection_verify.py report.json [--analysis-key <base64 uncompressed P-256 point>]

A report has three parts, and this prints one block of lines for each. It never combines them into one verdict.
  INTEGRITY  only cross-checked here (the AI block names the same photo and record the report names). The record, photo, hash chain,
             Apple evidence and time are checked by shield_verify.py, shield_vault_verify.py and shield_apple_verify.py.
  AI         the findings block is well formed, its hash and signature check out, and it is signed by the analysis key you pin with
             --analysis-key. Without a pinned key the embedded key only shows the block was not changed since whoever held that key
             signed it. Nothing here shows the findings are correct: with no evaluation run named the block is "not validated".
  HUMAN      a person's accept or reject for each finding, signed over the hash of the unchanged AI block. There is no edit: only
             accepted or rejected can be expressed. A finding with no decision is "AI, not reviewed".

Each line starts with CHECKED, FAILED, NOT CHECKED, NOT PRESENT, OUT OF SCOPE or LABEL. A pass is CHECKED; the others are never one.
Exit code: 0 nothing failed and nothing this tool owns was left unchecked; 2 a check failed; 3 nothing failed but something is missing or
not checked (no human approval, no pinned key, or an evaluation run this file cannot check).

Written from the format in docs/features/inspection-report.md. The Shield server's code is not imported.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
JS_SAFE_INT = 2 ** 53 - 1
CATEGORIES = ("material", "missing-step", "defect")
AI_FIELDS = {"version", "photo_sha256", "record_hash", "checkpoint_context_sha256", "model_id", "prompt_sha256", "raw_output_sha256",
             "evaluation_run_id", "created_at_ms", "kid", "findings"}
FINDING_FIELDS = {"id", "category", "status", "text", "confidence_permille"}
APPROVAL_FIELDS = {"version", "ai_block_sha256", "decisions", "reviewed_at_ms", "effort"}
APPROVAL_CHALLENGE = b"shield-approval-v1"


class Failed(Exception):
    pass


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _b64(value, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise Failed(f"{what} is not base64") from None


def _whole(value) -> bool:
    return type(value) is int and 0 <= value <= JS_SAFE_INT


def _hex(value) -> bool:
    return isinstance(value, str) and bool(HEX64.fullmatch(value))


def _text(value, limit) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit


def _public_key(b64: str, what: str) -> ec.EllipticCurvePublicKey:
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _b64(b64, what))
    except (ValueError, TypeError):
        raise Failed(f"{what} is not a P-256 public key") from None


def _check_block(block) -> None:
    if not isinstance(block, dict) or set(block) != AI_FIELDS or type(block["version"]) is not int or block["version"] != 1:
        raise Failed("the AI block does not have the fields of ai_findings.v1")
    if not all(_hex(block[n]) for n in ("photo_sha256", "record_hash", "checkpoint_context_sha256", "prompt_sha256", "raw_output_sha256")):
        raise Failed("a hash in the AI block is not 64 lowercase hex characters")
    if not _text(block["model_id"], 512) or not _text(block["kid"], 512) or not _whole(block["created_at_ms"]):
        raise Failed("the AI block has an invalid model id, key id or time")
    if block["evaluation_run_id"] is not None and not _text(block["evaluation_run_id"], 512):
        raise Failed("the evaluation run id is invalid")
    findings = block["findings"]
    if not isinstance(findings, list) or len(findings) > 64:
        raise Failed("findings is not a list of at most 64")
    ids = []
    for f in findings:
        if not isinstance(f, dict) or set(f) != FINDING_FIELDS or not isinstance(f["id"], str) or not ID.fullmatch(f["id"]):
            raise Failed("a finding does not have the fields of ai_findings.v1")
        if f["category"] not in CATEGORIES or f["status"] not in ("found", "abstain") or not _text(f["text"], 500):
            raise Failed(f"finding {f['id']} has an invalid category, status or text")
        c = f["confidence_permille"]
        if f["status"] == "abstain":
            if c is not None:
                raise Failed(f"abstention {f['id']} carries a confidence")
        elif type(c) is not int or not 0 <= c <= 1000:
            raise Failed(f"finding {f['id']} has an invalid confidence")
        ids.append(f["id"])
    if len(set(ids)) != len(ids):
        raise Failed("two findings share an id")


def _verify(public: ec.EllipticCurvePublicKey, signature_b64: str, data: bytes, what: str) -> None:
    try:
        public.verify(_b64(signature_b64, f"the {what} signature"), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Failed(f"the {what} signature does not verify") from None


def check_integrity(report: dict) -> list[tuple[str, str]]:
    integrity = report.get("integrity")
    if not isinstance(integrity, dict) or not _hex(integrity.get("record_hash")) or not _hex(integrity.get("photo_sha256")):
        raise Failed("the report names no photo and record (integrity.record_hash, integrity.photo_sha256)")
    return [("OUT OF SCOPE", "photo integrity: the record, photo, hash chain, Apple evidence and time are checked by shield_verify.py, "
                             "shield_vault_verify.py and shield_apple_verify.py, not here")]


def check_ai(report: dict, pinned_key_b64: str | None) -> tuple[list[tuple[str, str]], dict | None]:
    envelope = report.get("ai")
    if envelope is None:
        return [("NOT PRESENT", "no AI findings in this report")], None
    lines: list[tuple[str, str]] = []
    block = envelope["ai_block"]
    _check_block(block)
    lines.append(("CHECKED", "the AI block is well formed (ai_findings.v1)"))
    digest = hashlib.sha256(canonical(block)).hexdigest()
    if envelope.get("ai_block_sha256") != digest:
        raise Failed("ai_block_sha256 is not the hash of the block")
    integrity = report["integrity"]
    if block["photo_sha256"] != integrity["photo_sha256"] or block["record_hash"] != integrity["record_hash"]:
        raise Failed("the AI findings are about a different photo or record than the report names")
    lines.append(("CHECKED", f"the findings are bound to this photo ({block['photo_sha256'][:16]}…) and record, by hash"))
    point = _b64(envelope.get("public_key_uncompressed_b64"), "the analysis public key")
    public = _public_key(envelope["public_key_uncompressed_b64"], "the analysis public key")
    if hashlib.sha256(point).hexdigest()[:16] != block["kid"]:
        raise Failed("the block's key id is not the id of the embedded key")
    _verify(public, envelope.get("signature_der_b64"), canonical(block), "AI block")
    lines.append(("CHECKED", f"the block was not changed since it was signed by the holder of key {block['kid']}"))
    if pinned_key_b64:
        if _b64(pinned_key_b64, "--analysis-key") != point:
            raise Failed("the block is signed by a key other than the analysis key you pinned")
        lines.append(("CHECKED", "the signing key is the analysis key you pinned"))
    else:
        lines.append(("NOT CHECKED", "that the signing key is Shield's analysis key (pass --analysis-key with the published public key)"))
    found = [f for f in block["findings"] if f["status"] == "found"]
    lines.append(("CHECKED", f"{len(block['findings'])} findings: {len(found)} stated, {len(block['findings']) - len(found)} abstained; "
                             f"model {block['model_id']}"))
    if block["evaluation_run_id"] is None:
        lines.append(("LABEL", "AI findings, not validated: no evaluation run is named, so nothing here says how often this AI is right"))
    else:
        lines.append(("NOT CHECKED", f"evaluation run {block['evaluation_run_id']}: its results are not part of this file"))
    return lines, block


def check_human(report: dict, block: dict | None) -> list[tuple[str, str]]:
    approval_env = report.get("human_approval")
    if block is None:
        return [("NOT PRESENT", "no AI section, so nothing for a person to approve")]
    ids = [f["id"] for f in block["findings"]]
    if approval_env is None:
        return [("NOT PRESENT", "no human approval"), ("LABEL", f"AI, not reviewed: {len(ids)} findings have no human decision")]
    approval = approval_env["approval"]
    if not isinstance(approval, dict) or set(approval) != APPROVAL_FIELDS or type(approval["version"]) is not int or approval["version"] != 1:
        raise Failed("the approval does not have the fields of human_approval.v1")
    if approval["ai_block_sha256"] != hashlib.sha256(canonical(block)).hexdigest():
        raise Failed("the approval is for an AI block other than the one in this report")
    decisions = approval["decisions"]
    seen: dict[str, str] = {}
    if not isinstance(decisions, list):
        raise Failed("decisions is not a list")
    for d in decisions:
        if not isinstance(d, dict) or set(d) != {"finding_id", "decision"} or d["decision"] not in ("accepted", "rejected") \
                or d["finding_id"] not in ids or d["finding_id"] in seen:
            raise Failed("a decision is not accepted or rejected for exactly one finding of this block")
        seen[d["finding_id"]] = d["decision"]
    effort = approval["effort"]
    if not _whole(approval["reviewed_at_ms"]) or not isinstance(effort, dict) or set(effort) != {"shown_finding_ids", "screen_ms"} \
            or not isinstance(effort["shown_finding_ids"], list) or any(i not in ids for i in effort["shown_finding_ids"]) or not _whole(effort["screen_ms"]):
        raise Failed("the approval's time or review-effort record is invalid")
    if not set(seen) <= set(effort["shown_finding_ids"]):
        raise Failed("a finding was decided without being shown")
    lines = [("CHECKED", "the approval is well formed and names only this block's findings; it can only accept or reject")]
    point = _b64(approval_env.get("public_key_uncompressed_b64"), "the approver's public key")
    public = _public_key(approval_env["public_key_uncompressed_b64"], "the approver's public key")
    data = APPROVAL_CHALLENGE + hashlib.sha256(canonical(approval)).digest()
    _verify(public, approval_env.get("signature_der_b64"), data, "approval")
    lines.append(("CHECKED", "the approval was signed by the holder of its key over the unchanged AI block"))
    photo_key = report["integrity"].get("public_key_uncompressed_b64")
    if photo_key is not None:
        same = _b64(photo_key, "integrity.public_key_uncompressed_b64") == point
        lines.append(("CHECKED", "approved with the same key that signed the photo" if same else "approved with a different key than the one that signed the photo"))
    lines.append(("OUT OF SCOPE", "that the approver's key is held in phone hardware: that needs Apple evidence for that key (shield_apple_verify.py)"))
    accepted = [i for i, d in seen.items() if d == "accepted"]
    rejected = [i for i, d in seen.items() if d == "rejected"]
    unreviewed = [i for i in ids if i not in seen]
    lines.append(("CHECKED", f"decisions: {len(accepted)} accepted, {len(rejected)} rejected, {len(unreviewed)} not reviewed; "
                             f"{effort['screen_ms']} ms on screen (recorded, not a quality claim)"))
    if unreviewed:
        lines.append(("LABEL", "AI, not reviewed: " + ", ".join(unreviewed)))
    return lines


def check(report, pinned_key_b64: str | None = None) -> tuple[int, list[tuple[str, str]]]:
    out: list[tuple[str, str]] = []
    try:
        if not isinstance(report, dict) or type(report.get("report_version")) is not int or report["report_version"] != 1:
            raise Failed("not an inspection report (report_version 1)")
        out.append(("", "== PHOTO INTEGRITY =="))
        out += check_integrity(report)
        out.append(("", "== AI FINDINGS =="))
        ai_lines, block = check_ai(report, pinned_key_b64)
        out += ai_lines
        out.append(("", "== HUMAN APPROVAL =="))
        out += check_human(report, block)
    except Failed as exc:
        return 2, out + [("FAILED", str(exc))]
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return 2, out + [("FAILED", f"the report is malformed ({type(exc).__name__}: {exc})")]
    open_items = any(tag in ("NOT CHECKED", "NOT PRESENT") for tag, _ in out)
    return (3 if open_items else 0), out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check an inspection report's AI findings and human approval offline.")
    ap.add_argument("report", help="inspection report JSON")
    ap.add_argument("--analysis-key", help="Shield's published analysis public key (base64, uncompressed P-256 point)")
    args = ap.parse_args(argv)
    with open(args.report, encoding="utf-8") as fh:
        report = json.load(fh)
    code, lines = check(report, args.analysis_key)
    for tag, text in lines:
        print(f"{tag:<12} {text}" if tag else text)
    return code


if __name__ == "__main__":
    sys.exit(main())
