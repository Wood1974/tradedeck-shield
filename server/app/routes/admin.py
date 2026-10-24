from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..auth import actor_for
from ._common import local_admin
from .auth import LocalLogin

router = APIRouter()


def _m():
    # main.py owns the shared store and attestation verifiers; tests patch them there, so read them when a request arrives.
    from .. import main
    return main

class LocalAccountCreate(LocalLogin):
    role: str = "capturer"

class LocalJobGrant(BaseModel):
    account_id: str
    job_id: str
    point_id: str

class LocalPasswordReset(BaseModel):
    password: str


@router.post("/shield/admin/accounts")
def local_create_account(request:Request,body:LocalAccountCreate):
    local,_=local_admin(request)
    try: account=local.create_account(body.email,body.password,body.role)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"account_id":account.id,"email":account.email,"role":account.role}

@router.post("/shield/admin/job-grants")
def local_grant_job(request:Request,body:LocalJobGrant):
    local,admin=local_admin(request)
    try: local.grant(admin,body.account_id,body.job_id,body.point_id)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"granted":True,**body.model_dump()}

@router.delete("/shield/admin/job-grants")
def local_revoke_job(request:Request,body:LocalJobGrant):
    local,admin=local_admin(request)
    local.revoke(admin,body.account_id,body.job_id,body.point_id)
    return {"revoked":True}

@router.post("/shield/admin/accounts/{account_id}/deactivate")
def local_deactivate_account(request:Request,account_id:str):
    local,admin=local_admin(request)
    try: local.deactivate(admin,account_id)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"deactivated":True}

@router.post("/shield/admin/accounts/{account_id}/reset-password")
def local_reset_password(request:Request,account_id:str,body:LocalPasswordReset):
    local,_=local_admin(request)
    try: local.reset_password(account_id,body.password)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"reset":True,"tokens_revoked":True}


@router.get("/shield/admin/health")
def admin_health(request:Request):
    from ..local_identity import admin_locked
    if admin_locked(): raise HTTPException(403,"admin_locked")
    actor=actor_for(request,None)
    if os.getenv("SHIELD_API_AUTH_MODE","development") == "local":
        if actor.claims.get("role") != "admin": raise HTTPException(403,"admin_required")
        return {"ok":True,"attestation_mode":_m().att_mode,"authz_mode":"local","timestamp_required":os.getenv("SHIELD_TIMESTAMP_REQUIRED","false").lower()=="true"}
    admins={x.strip() for x in os.getenv("SHIELD_ADMIN_ACCOUNT_IDS","").split(",") if x.strip()}
    if actor.account_id not in admins: raise HTTPException(403,"admin_required")
    return {"ok":True,"attestation_mode":_m().att_mode,"authz_mode":os.getenv("SHIELD_AUTHZ_MODE","development"),"timestamp_required":os.getenv("SHIELD_TIMESTAMP_REQUIRED","false").lower()=="true"}
