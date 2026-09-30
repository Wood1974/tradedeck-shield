"""Independent Shield evidence verification.

Verification is deliberately deterministic: it recomputes protocol hashes from
bytes/statements instead of trusting a capture-client verdict.
"""
from __future__ import annotations
from .protocol import sha256_bytes, bind_hash
from .attestation_sheet import AttestationSheet
from .custody_chain import verify_chain
from .state_machine import EvidenceStateMachine
import json

SEALED_STATES = {"sealed", "amended", "voided"}

def verify_record(row, stored_original: bytes | None, supplied_original: bytes | None = None,
                  location_stated: str | None = None, purpose: str | None = None,
                  state_history=None, custody_events=None) -> dict:
    checks: dict[str, dict] = {}

    if stored_original is None:
        stored_photo_hash = None
        checks["stored_original"] = {"ok": False, "reason": "original_missing"}
    else:
        stored_photo_hash = sha256_bytes(stored_original)
        checks["stored_original"] = {"ok": stored_photo_hash == row["photo_sha256"]}

    photo_hash = stored_photo_hash
    if supplied_original is not None:
        supplied_hash = sha256_bytes(supplied_original)
        checks["supplied_original"] = {"ok": supplied_hash == row["photo_sha256"], "sha256": supplied_hash}
        photo_hash = supplied_hash

    supplied_note_hash = None
    if location_stated is not None or purpose is not None:
        try:
            sheet = AttestationSheet.from_user_input(location_stated, purpose)
            supplied_note_hash = sheet.sha256
            checks["attestation_sheet"] = {"ok": supplied_note_hash == row["note_sha256"], "sha256": supplied_note_hash}
        except ValueError as exc:
            checks["attestation_sheet"] = {"ok": False, "reason": str(exc)}
    else:
        checks["attestation_sheet"] = {"ok": None, "reason": "not_supplied"}

    effective_note_hash = supplied_note_hash or row["note_sha256"]
    stored_sheet = row["attestation_sheet_json"] if "attestation_sheet_json" in row.keys() else None
    if stored_sheet:
        try:
            testimony = json.loads(stored_sheet)
            sheet = AttestationSheet.from_user_input(testimony.get("location_stated"), testimony.get("purpose"))
            checks["stored_attestation_sheet"] = {"ok": sheet.sha256 == row["note_sha256"]}
        except (ValueError, TypeError, AttributeError):
            checks["stored_attestation_sheet"] = {"ok": False, "reason": "invalid_stored_testimony"}
    else:
        required = row["attestation_sheet_required"] if "attestation_sheet_required" in row.keys() else False
        checks["stored_attestation_sheet"] = {"ok": False if required else None, "reason": "stored_testimony_missing" if required else "legacy_record_testimony_not_retained"}
    if photo_hash is not None:
        recomputed_bind = bind_hash(photo_hash, effective_note_hash, row["job_id"], row["point_id"], row["nonce"], row["account_id"])
        checks["bind_hash"] = {"ok": recomputed_bind == row["bind_hash"], "recomputed": recomputed_bind}
    else:
        checks["bind_hash"] = {"ok": False, "reason": "photo_unavailable"}

    state = row["state"]
    history = list(state_history or [])
    state_ok = state in SEALED_STATES and bool(history) and history[-1]["to_state"] == state
    if state_ok:
        previous = None
        for event in history:
            if event["from_state"] != previous:
                state_ok = False
                break
            if previous is None:
                if event["to_state"] != "capture_received":
                    state_ok = False
                    break
            elif not EvidenceStateMachine(previous).can_transition(event["to_state"]):
                state_ok = False
                break
            previous = event["to_state"]
    checks["state_history"] = {"ok": state_ok, "state": state, "events": len(history)}

    custody = list(custody_events or [])
    chain = verify_chain(custody)
    checks["custody_chain"] = {"ok": chain["valid"], "events": len(custody)}
    sealed = [e for e in custody if e["event_type"] == "sealed"]
    custody_ok = bool(sealed)
    if sealed:
        try:
            d = json.loads(sealed[-1]["details_json"] or "{}")
            custody_ok = (d.get("photo_sha256") == row["photo_sha256"] and
                          d.get("note_sha256") == row["note_sha256"] and
                          d.get("bind_hash") == row["bind_hash"])
        except Exception:
            custody_ok = False
    checks["custody_seal"] = {"ok": custody_ok, "sealed_events": len(sealed)}
    if state in {"amended", "voided"}:
        checks["custody_state"] = {"ok": bool(custody) and custody[-1]["event_type"] == state}

    failed = [k for k,v in checks.items() if v.get("ok") is False]
    # Optional attestation sheet does not prevent verification when omitted;
    # in that case the stored note hash remains part of the bind calculation.
    ok = not failed
    return {
        "ok": ok,
        "evidence_id": row["id"],
        "protocol": "shield-evidence-v1",
        "state": state,
        "written_at": row["written_at"],
        "checks": checks,
        "failed_checks": failed,
        "limitations": [
            "Verification proves consistency with the Shield record; it does not prove the truth of the human statement.",
            "Location is a signal and is never reported as GPS-verified.",
            "This verifier relies on server-held records; it does not establish immutable storage or validate an external timestamp token."
        ]
    }
