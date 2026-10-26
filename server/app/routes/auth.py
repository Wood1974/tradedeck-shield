from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..auth import actor_for
from ..security import login_failed, login_succeeded, login_throttle_check

router = APIRouter()


def _m():
    # main.py owns the shared store and attestation verifiers; tests patch them there, so read them when a request arrives.
    from .. import main
    return main

class LocalLogin(BaseModel):
    email: str
    password: str


@router.post("/shield/auth/login")
def local_login(body:LocalLogin):
    if os.getenv("SHIELD_API_AUTH_MODE", "development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    from ..local_identity import identity, TOKEN_TTL_SECONDS
    login_throttle_check(body.email)
    try:
        local=identity()
        account=local.authenticate(body.email,body.password)
        if not account:
            login_failed(body.email)
            raise HTTPException(401,"invalid_credentials")
        token=local.token(account)
    except RuntimeError as exc:
        raise HTTPException(503,str(exc)) from exc
    login_succeeded(body.email)
    return {"access_token":token,"token_type":"bearer","expires_in":TOKEN_TTL_SECONDS,
            "account_id":account.id,"role":account.role}

class ForgotPassword(BaseModel):
    email: str

class ResetPassword(BaseModel):
    email: str
    code: str
    new_password: str

@router.post("/shield/auth/forgot")
def local_forgot_password(body:ForgotPassword):
    if os.getenv("SHIELD_API_AUTH_MODE", "development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    from .. import password_reset
    from ..local_identity import identity
    try:
        password_reset.request_code(identity(),body.email)
    except password_reset.MailNotConfigured as exc:
        raise HTTPException(503,"email_not_configured") from exc
    except RuntimeError as exc:
        raise HTTPException(503,str(exc)) from exc
    # The same answer whether or not the email has an account, and whether or not a code was sent.
    return {"ok":True}

@router.post("/shield/auth/reset")
def local_reset_password_with_code(body:ResetPassword):
    if os.getenv("SHIELD_API_AUTH_MODE", "development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    from .. import password_reset
    from ..local_identity import identity
    try:
        password_reset.confirm_reset(identity(),body.email,body.code,body.new_password)
    except ValueError as exc:
        raise HTTPException(400 if str(exc)==password_reset.GENERIC_FAILURE else 422,str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(503,str(exc)) from exc
    return {"ok":True,"signed_out_everywhere":True}

@router.get("/shield/auth/me")
def local_me(request:Request):
    actor=actor_for(request,None)
    return {"account_id":actor.account_id,"role":actor.claims.get("role")}

@router.get("/shield/jobs")
def local_jobs(request:Request):
    if os.getenv("SHIELD_API_AUTH_MODE","development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    actor=actor_for(request,None)
    from ..local_identity import identity
    return {"jobs":identity().grants_for(actor.account_id)}
