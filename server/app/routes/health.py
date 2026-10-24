from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()


def _m():
    # main.py owns the shared store and attestation verifiers; tests patch them there, so read them when a request arrives.
    from .. import main
    return main

@router.get("/verify", include_in_schema=False)
def verification_viewer():
    return FileResponse(os.path.join(os.path.dirname(__file__),"..","static","verify.html"))

@router.get("/health")
def health():
    return {"ok": True, "service": "tradedeck-shield", "protocol": "shield-evidence-v1", "api": "1.1"}

@router.get("/shield/v1/health")
def shield_health():
    if os.getenv("SHIELD_API_AUTH_MODE") == "local":
        if len(os.getenv("SHIELD_LOCAL_JWT_SECRET","").encode("utf-8")) < 32:
            raise HTTPException(503,"local_jwt_secret_not_configured")
        if os.getenv("SHIELD_AUTHZ_MODE") != "local":
            raise HTTPException(503,"local_job_authorization_not_configured")
    if os.getenv("SHIELD_ATTESTATION_MODE") == "production" and not os.getenv("SHIELD_APP_ID", "").strip():
        raise HTTPException(503,"apple_app_id_not_configured")
    if os.getenv("SHIELD_PLAY_INTEGRITY_MODE") == "production":
        if not os.getenv("SHIELD_PLAY_PACKAGE_NAME", "").strip():
            raise HTTPException(503,"play_package_not_configured")
        credentials=os.getenv("GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON", "").strip()
        credentials_file=os.getenv("GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE", "").strip()
        if not (credentials or credentials_file):
            raise HTTPException(503,"play_integrity_credentials_not_configured")
        try:
            info=json.loads(credentials) if credentials else json.loads(Path(credentials_file).read_text(encoding="utf-8"))
            if not isinstance(info,dict) or not all(info.get(k) for k in ("client_email","private_key","token_uri")):
                raise ValueError("incomplete_service_account")
        except (OSError,ValueError,TypeError) as exc:
            raise HTTPException(503,"play_integrity_credentials_invalid") from exc
    return {"ok": True, "service": "tradedeck-shield", "protocol": "shield-evidence-v1", "api": "1.1"}
