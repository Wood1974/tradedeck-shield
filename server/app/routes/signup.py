from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..security import enforce_rate_limit
from ._common import local_admin

router = APIRouter()


class SignUp(BaseModel):
    email: str
    password: str
    invite_code: str


class InviteMint(BaseModel):
    count: int = 1
    days: int = 14
    note: str = ""


@router.post("/shield/auth/signup")
def local_signup(request:Request,body:SignUp):
    if os.getenv("SHIELD_API_AUTH_MODE", "development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    enforce_rate_limit(request)
    from .. import signup
    from ..local_identity import identity
    try:
        signup.create_account_with_invite(identity(),body.email,body.password,body.invite_code)
    except ValueError as exc:
        reason=str(exc)
        raise HTTPException(400 if reason==signup.GENERIC_FAILURE else 409 if reason=="account_already_exists" else 422,reason) from exc
    except RuntimeError as exc:
        raise HTTPException(503,str(exc)) from exc
    return {"ok":True}


@router.post("/shield/admin/invites")
def local_mint_invites(request:Request,body:InviteMint):
    local,admin=local_admin(request)
    from .. import signup
    try: codes=signup.mint(local,admin.id,body.count,body.days,body.note)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"codes":codes,"expires_in_days":body.days}
