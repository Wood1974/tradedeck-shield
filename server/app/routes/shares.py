from __future__ import annotations

import os

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ..security import enforce_rate_limit
from ._common import local_account_id

router = APIRouter()


def _m():
    # main.py owns the shared settings; read them when a request arrives.
    from .. import main
    return main


class ShareRequest(BaseModel):
    days: int = 30

@router.post("/shield/captures/{record_hash}/share")
def create_share(request:Request,record_hash:str,body:ShareRequest):
    account_id=local_account_id(request)
    enforce_rate_limit(request)
    from .. import shares
    from ..local_identity import identity
    try:
        made=shares.create(identity(),account_id,record_hash,body.days)
    except ValueError as exc:
        raise HTTPException(422,str(exc)) from exc
    if made is None: raise HTTPException(404,"not_found")
    return made

@router.get("/shield/captures/{record_hash}/shares")
def list_shares(request:Request,record_hash:str):
    account_id=local_account_id(request)
    from .. import shares
    from ..local_identity import identity
    found=shares.list_for(identity(),account_id,record_hash)
    if found is None: raise HTTPException(404,"not_found")
    return {"shares":found}

@router.delete("/shield/shares/{share_id}")
def revoke_share(request:Request,share_id:str):
    account_id=local_account_id(request)
    from .. import shares
    from ..local_identity import identity
    if not shares.revoke(identity(),account_id,share_id): raise HTTPException(404,"not_found")
    return {"ok":True}

@router.post("/shield/v1/compare")
async def compare_with_server(request:Request,code:str=Form(...),photo:UploadFile=File(...)):
    """Anyone holding a share code and the original file can ask whether it is the file Shield stored. No account.

    A bad code of any kind answers the same 404, so nothing is revealed without a code. The file is read in memory and dropped."""
    if os.getenv("SHIELD_API_AUTH_MODE","development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    enforce_rate_limit(request)
    from .. import shares
    from ..local_identity import identity
    if not shares.enforce_compare_limit(): raise HTTPException(429,"rate_limit_exceeded")
    data=await photo.read(_m().MAX_PHOTO_BYTES + 1)
    if len(data) > _m().MAX_PHOTO_BYTES: raise HTTPException(413,"photo_too_large")
    if not data: raise HTTPException(400,"empty_photo")
    result=shares.compare(identity(),code,data)
    if result is None: raise HTTPException(404,"not_found")
    return result

@router.get("/check", include_in_schema=False)
def share_checker():
    return FileResponse(os.path.join(os.path.dirname(__file__),"..","..","static","check.html"))
