from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request

from ._common import local_account_id

router = APIRouter()


@router.get("/shield/captures/{record_hash}/evidence")
def capture_evidence(request: Request, record_hash: str):
    """Everything this server holds that someone else can check without trusting it, for the account that owns the photo.

    Each part says plainly when it was not kept, so a gap is never read as a pass: a photo or key stored before the evidence was
    kept has none, and an assertion is only sent by a phone that made one."""
    account_id = local_account_id(request)
    from .. import attestation_evidence, captures, main, outside_time
    from ..local_identity import identity
    if len(record_hash) != 64 or any(c not in "0123456789abcdef" for c in record_hash):
        raise HTTPException(404, "not_found")
    local = identity()
    row = captures.row_for(local, account_id, record_hash)
    if row is None:
        raise HTTPException(404, "not_found")
    key_id, assertion = row["attest_key_id"], row["attest_assertion_b64"]
    kept = attestation_evidence.get(main.store, key_id, account_id) if key_id else None
    apple: dict = {"key_id": key_id, "server_verdict": row["attest_status"], "server_trusted": bool(row["attest_trusted"])}
    if kept and assertion:
        apple.update(kept=True, attestation_b64=kept["attestation_b64"], challenge=kept["challenge"], app_id=kept["app_id"],
                     environment=kept["environment"], assertion_b64=assertion)
    else:
        why = "no phone key was sent with this photo" if not key_id else (
            "the phone sent no assertion with this photo" if not assertion else
            "this phone key was enrolled before the server kept Apple's attestation; enrol it again to get evidence for new photos")
        apple.update(kept=False, reason=why)
    return {
        "record_hash": record_hash,
        "record": json.loads(row["record_json"]),
        "signature_der_b64": row["signature_der_b64"],
        "public_key_uncompressed_b64": row["public_key_b64"],
        "apple": apple,
        "outside_time": outside_time.token_for(local, account_id, record_hash),
    }
