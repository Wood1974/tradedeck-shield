"""The format of an inspection report's AI section and its human approval. No AI is called here.

A report has three parts that are never merged into one verdict:
1. Photo integrity: the hardware-signed record, checked by verifier/shield_verify.py and verifier/shield_apple_verify.py. Not this file.
2. AI findings (`ai_findings.v1`): what a model said about one stored photo, signed by a Shield analysis key. The signature binds the
   findings to that photo's hash, the model id, the prompt, the checkpoint context and the model's raw output. It shows the findings
   were not changed after signing. It does not show they are right: correctness is the evaluation's job, and until an evaluation run
   is named the block says so (`evaluation_run_id` is null = not validated).
3. Human approval (`human_approval.v1`): a person's accept or reject for each finding, signed by a phone's hardware key over the hash of
   the unchanged AI block. There is no edit: a decision is `accepted` or `rejected`, and nothing else can be expressed. A finding with
   no decision stays "AI, not reviewed".

The analysis key is SHIELD_ANALYSIS_SIGNING_KEY_PEM (P-256 private key in PEM), separate from the ticket key. Without it, signing
is closed. verifier/shield_inspection_verify.py re-checks all of this without importing this file; test_inspection_report.py keeps the two in agreement.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

AI_VERSION = 1
APPROVAL_VERSION = 1
APPROVAL_CHALLENGE = b"shield-approval-v1"
CATEGORIES = ("material", "missing-step", "defect")
STATUSES = ("found", "abstain")
DECISIONS = ("accepted", "rejected")
JS_SAFE_INT = 2 ** 53 - 1
MAX_FINDINGS = 64
MAX_TEXT = 500
MAX_TEXT_FIELD = 512
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

AI_FIELDS = ("version", "photo_sha256", "record_hash", "checkpoint_context_sha256", "model_id", "prompt_sha256",
             "raw_output_sha256", "evaluation_run_id", "created_at_ms", "kid", "findings")
FINDING_FIELDS = ("id", "category", "status", "text", "confidence_permille")
APPROVAL_FIELDS = ("version", "ai_block_sha256", "decisions", "reviewed_at_ms", "effort")
EFFORT_FIELDS = ("shown_finding_ids", "screen_ms")


class AnalysisClosed(Exception):
    """The deployment has no usable analysis signing key."""


class Invalid(ValueError):
    """Not a well-formed block. The message is a stable code."""


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def _key() -> ec.EllipticCurvePrivateKey:
    pem = os.getenv("SHIELD_ANALYSIS_SIGNING_KEY_PEM", "")
    if not pem.strip():
        raise AnalysisClosed("analysis_closed")
    try:
        key = serialization.load_pem_private_key(pem.replace("\\n", "\n").encode(), password=None)
    except (ValueError, TypeError):
        raise AnalysisClosed("analysis_key_invalid") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise AnalysisClosed("analysis_key_invalid")
    return key


def public_point(key=None) -> bytes:
    key = key or _key()
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def key_id(key=None) -> str:
    return hashlib.sha256(public_point(key)).hexdigest()[:16]


def public_info() -> dict:
    return {"kid": key_id(), "public_key_uncompressed_b64": base64.b64encode(public_point()).decode("ascii")}


def _whole(value) -> int:
    if type(value) is not int or value < 0 or value > JS_SAFE_INT:
        raise Invalid("field_invalid")
    return value


def _hex(value) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise Invalid("hash_invalid")
    return value


def _text(value, limit=MAX_TEXT_FIELD) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise Invalid("text_invalid")
    return value


def _finding(f) -> dict:
    if not isinstance(f, dict) or set(f) != set(FINDING_FIELDS):
        raise Invalid("finding_invalid")
    if not isinstance(f["id"], str) or not _ID.fullmatch(f["id"]):
        raise Invalid("finding_invalid")
    if f["category"] not in CATEGORIES or f["status"] not in STATUSES:
        raise Invalid("finding_invalid")
    _text(f["text"], MAX_TEXT)
    c = f["confidence_permille"]
    if f["status"] == "abstain":
        if c is not None:
            raise Invalid("finding_invalid")  # an abstention carries no confidence; the text says why
    elif type(c) is not int or not 0 <= c <= 1000:
        raise Invalid("finding_invalid")
    return f


def validated_ai_block(block) -> dict:
    if not isinstance(block, dict) or set(block) != set(AI_FIELDS) or type(block["version"]) is not int or block["version"] != AI_VERSION:
        raise Invalid("ai_block_invalid")
    for name in ("photo_sha256", "record_hash", "checkpoint_context_sha256", "prompt_sha256", "raw_output_sha256"):
        _hex(block[name])
    _text(block["model_id"])
    _text(block["kid"])
    _whole(block["created_at_ms"])
    if block["evaluation_run_id"] is not None:
        _text(block["evaluation_run_id"])
    findings = block["findings"]
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise Invalid("finding_invalid")
    ids = [_finding(f)["id"] for f in findings]
    if len(set(ids)) != len(ids):
        raise Invalid("finding_invalid")
    return block


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def ai_block_sha256(block: dict) -> str:
    return hashlib.sha256(canonical(validated_ai_block(block))).hexdigest()


def sign_ai_block(*, photo_sha256: str, record_hash: str, checkpoint_context_sha256: str, model_id: str, prompt_sha256: str,
                  raw_output_sha256: str, findings: list, evaluation_run_id: str | None = None, now=now_ms) -> dict:
    """The signed AI section for one photo. Raises AnalysisClosed with no key, Invalid for a malformed block."""
    key = _key()
    block = validated_ai_block({"version": AI_VERSION, "photo_sha256": photo_sha256, "record_hash": record_hash,
                                "checkpoint_context_sha256": checkpoint_context_sha256, "model_id": model_id,
                                "prompt_sha256": prompt_sha256, "raw_output_sha256": raw_output_sha256,
                                "evaluation_run_id": evaluation_run_id, "created_at_ms": now(), "kid": key_id(key), "findings": findings})
    signature = key.sign(canonical(block), ec.ECDSA(hashes.SHA256()))
    return {"ai_block": block, "ai_block_sha256": hashlib.sha256(canonical(block)).hexdigest(),
            "signature_der_b64": base64.b64encode(signature).decode("ascii"),
            "public_key_uncompressed_b64": base64.b64encode(public_point(key)).decode("ascii")}


def validated_approval(approval, ai_block: dict) -> dict:
    """An approval is accept or reject per finding of the block it names, and nothing else."""
    if not isinstance(approval, dict) or set(approval) != set(APPROVAL_FIELDS) or type(approval["version"]) is not int or approval["version"] != APPROVAL_VERSION:
        raise Invalid("approval_invalid")
    if _hex(approval["ai_block_sha256"]) != ai_block_sha256(ai_block):
        raise Invalid("approval_for_another_block")
    known = {f["id"] for f in ai_block["findings"]}
    decisions = approval["decisions"]
    if not isinstance(decisions, list):
        raise Invalid("approval_invalid")
    seen = set()
    for d in decisions:
        if not isinstance(d, dict) or set(d) != {"finding_id", "decision"} or d["decision"] not in DECISIONS or d["finding_id"] not in known or d["finding_id"] in seen:
            raise Invalid("approval_invalid")
        seen.add(d["finding_id"])
    _whole(approval["reviewed_at_ms"])
    effort = approval["effort"]
    if not isinstance(effort, dict) or set(effort) != set(EFFORT_FIELDS) or not isinstance(effort["shown_finding_ids"], list) \
            or any(i not in known for i in effort["shown_finding_ids"]):
        raise Invalid("approval_invalid")
    _whole(effort["screen_ms"])
    if not seen <= set(effort["shown_finding_ids"]):
        raise Invalid("approval_invalid")  # a finding cannot be decided without having been shown
    return approval


def approval_client_data(approval: dict) -> bytes:
    """What the phone's hardware key signs: the challenge followed by SHA256 of the canonical approval."""
    return APPROVAL_CHALLENGE + hashlib.sha256(canonical(approval)).digest()
