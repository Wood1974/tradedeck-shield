from __future__ import annotations

import json

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, ValidationError

from ..security import enforce_rate_limit
from ._common import local_account_id

router = APIRouter()


def _m():
    from .. import main
    return main


class CaptureMeta(BaseModel):
    """The JSON upload of POST /shield/captures, without the photo."""
    record: dict
    signature_der_b64: str
    public_key_uncompressed_b64: str
    app_attest_key_id: str | None = None
    app_attest_assertion_b64: str | None = None


@router.post("/shield/captures/upload")
async def store_capture_multipart(request: Request, meta: str = Form(...), photo: UploadFile = File(...)):
    """The same checks and the same reply as POST /shield/captures, with the photo as raw bytes instead of base64 (a third smaller on the wire)."""
    account_id = local_account_id(request)
    enforce_rate_limit(request)
    if len(meta) > 64 * 1024:
        raise HTTPException(422, "record_invalid")
    try:
        parsed = CaptureMeta(**json.loads(meta))
    except (ValueError, TypeError, ValidationError) as exc:
        raise HTTPException(422, "record_invalid") from exc
    limit = _m().MAX_PHOTO_BYTES
    data = await photo.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, "photo_too_large")
    from .. import captures
    from ..local_identity import identity
    try:
        return captures.ingest(identity(), _m().att, account_id, parsed.model_dump(), photo_bytes=data)
    except captures.Refused as exc:
        reason = str(exc)
        raise HTTPException(413 if reason in {"photo_too_large", "quota_exceeded"} else 422, reason) from exc
