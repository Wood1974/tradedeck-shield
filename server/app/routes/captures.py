from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from ..security import enforce_rate_limit
from ._common import local_account_id

router = APIRouter()

class CaptureUpload(BaseModel):
    record: dict
    signature_der_b64: str
    public_key_uncompressed_b64: str
    photo_b64: str
    app_attest_key_id: str | None = None
    app_attest_assertion_b64: str | None = None

@router.post("/shield/captures")
def store_capture(request:Request,body:CaptureUpload):
    account_id=local_account_id(request)
    enforce_rate_limit(request)
    from .. import captures, main
    from ..local_identity import identity
    try:
        return captures.ingest(identity(),main.att,account_id,body.model_dump())
    except captures.Refused as exc:
        reason=str(exc)
        raise HTTPException(413 if reason in {"photo_too_large","quota_exceeded"} else 422,reason) from exc

@router.get("/shield/captures")
def list_captures(request:Request):
    account_id=local_account_id(request)
    from .. import captures
    from ..local_identity import identity
    return {"captures":captures.list_for(identity(),account_id)}

@router.get("/shield/captures/{record_hash}/photo")
def capture_photo(request:Request,record_hash:str):
    account_id=local_account_id(request)
    from .. import captures
    from ..local_identity import identity
    try:
        data=captures.read_photo(identity(),account_id,record_hash)
    except captures.Refused as exc:
        raise HTTPException(409,str(exc)) from exc
    if data is None: raise HTTPException(404,"not_found")
    return Response(data,media_type="image/jpeg",headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"})

@router.get("/shield/captures/{record_hash}/timestamp")
def capture_timestamp(request:Request,record_hash:str):
    account_id=local_account_id(request)
    from .. import outside_time
    from ..local_identity import identity
    if len(record_hash)!=64 or any(c not in "0123456789abcdef" for c in record_hash): raise HTTPException(404,"not_found")
    found=outside_time.token_for(identity(),account_id,record_hash)
    if found is None: raise HTTPException(404,"not_found")
    return found
