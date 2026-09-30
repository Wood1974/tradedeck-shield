from __future__ import annotations
from datetime import datetime, timezone
import json, os, uuid
from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from .protocol import sha256_bytes, bind_hash
from .store import Store
from .attestation import AttestationVerifier
from .play_integrity import PlayIntegrityVerifier
from .auth import actor_for
from .location import evaluate_location
from .attestation_sheet import AttestationSheet
from .verification import verify_record
from .permissions import authorize_job, AuthorizationError
from .timestamping import timestamp_bind_hash
from .custody_chain import verify_chain
from .capture_packs import PACKS
from .security import enforce_rate_limit

app=FastAPI(title="TradeDeck Shield Evidence API", version="2.0.0", docs_url="/docs" if os.getenv("SHIELD_ENABLE_DOCS","false").lower()=="true" else None, redoc_url=None)
MAX_PHOTO_BYTES=int(os.getenv("SHIELD_MAX_PHOTO_BYTES","15728640"))
ALLOWED_IMAGE_TYPES={"image/jpeg","image/jpg"}
store=Store(os.getenv("SHIELD_DATABASE_URL","sqlite:///./shield.db"), os.getenv("SHIELD_STORAGE_ROOT","./storage"))
att_mode=os.getenv("SHIELD_ATTESTATION_MODE","development")
att=AttestationVerifier(att_mode,os.getenv("SHIELD_APP_ID",""),store=store)
play=PlayIntegrityVerifier(os.getenv("SHIELD_PLAY_INTEGRITY_MODE",att_mode),os.getenv("SHIELD_PLAY_PACKAGE_NAME", "com.tradedeck.shield"))
TTL=int(os.getenv("SHIELD_CHALLENGE_TTL_SECONDS","120"))

def enabled_platforms():
    platforms = {p.strip() for p in os.getenv("SHIELD_ENABLED_PLATFORMS", "ios,android").split(",") if p.strip()}
    if not platforms or not platforms <= {"ios", "android"}:
        raise HTTPException(503, "enabled_platforms_invalid")
    return platforms

class LocalLogin(BaseModel):
    email: str
    password: str

class LocalAccountCreate(LocalLogin):
    role: str = "capturer"

class LocalJobGrant(BaseModel):
    account_id: str
    job_id: str
    point_id: str

class LocalPasswordReset(BaseModel):
    password: str

class LocalJobLocation(BaseModel):
    job_id: str
    latitude: float
    longitude: float

def local_admin(request:Request):
    if os.getenv("SHIELD_API_AUTH_MODE", "development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    actor=actor_for(request,None)
    if actor.claims.get("role") != "admin":
        raise HTTPException(403,"admin_required")
    from .local_identity import LocalAccount, identity
    return identity(),LocalAccount(actor.account_id,"", "admin")

@app.post("/shield/auth/login")
def local_login(body:LocalLogin):
    if os.getenv("SHIELD_API_AUTH_MODE", "development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    from .local_identity import identity, TOKEN_TTL_SECONDS
    try:
        local=identity()
        account=local.authenticate(body.email,body.password)
        if not account: raise HTTPException(401,"invalid_credentials")
        token=local.token(account)
    except RuntimeError as exc:
        raise HTTPException(503,str(exc)) from exc
    return {"access_token":token,"token_type":"bearer","expires_in":TOKEN_TTL_SECONDS,
            "account_id":account.id,"role":account.role}

@app.get("/shield/auth/me")
def local_me(request:Request):
    actor=actor_for(request,None)
    return {"account_id":actor.account_id,"role":actor.claims.get("role")}

@app.get("/shield/jobs")
def local_jobs(request:Request):
    if os.getenv("SHIELD_API_AUTH_MODE","development") != "local":
        raise HTTPException(404,"local_identity_disabled")
    actor=actor_for(request,None)
    from .local_identity import identity
    return {"jobs":identity().grants_for(actor.account_id)}

@app.post("/shield/admin/accounts")
def local_create_account(request:Request,body:LocalAccountCreate):
    local,_=local_admin(request)
    try: account=local.create_account(body.email,body.password,body.role)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"account_id":account.id,"email":account.email,"role":account.role}

@app.post("/shield/admin/job-grants")
def local_grant_job(request:Request,body:LocalJobGrant):
    local,admin=local_admin(request)
    try: local.grant(admin,body.account_id,body.job_id,body.point_id)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"granted":True,**body.model_dump()}

@app.put("/shield/admin/job-locations")
def local_set_job_location(request:Request,body:LocalJobLocation):
    local,admin=local_admin(request)
    try: local.set_job_location(admin,body.job_id,body.latitude,body.longitude)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"saved":True,**body.model_dump()}

@app.delete("/shield/admin/job-grants")
def local_revoke_job(request:Request,body:LocalJobGrant):
    local,admin=local_admin(request)
    local.revoke(admin,body.account_id,body.job_id,body.point_id)
    return {"revoked":True}

@app.post("/shield/admin/accounts/{account_id}/deactivate")
def local_deactivate_account(request:Request,account_id:str):
    local,admin=local_admin(request)
    try: local.deactivate(admin,account_id)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"deactivated":True}

@app.post("/shield/admin/accounts/{account_id}/reset-password")
def local_reset_password(request:Request,account_id:str,body:LocalPasswordReset):
    local,_=local_admin(request)
    try: local.reset_password(account_id,body.password)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    return {"reset":True,"tokens_revoked":True}

@app.middleware("http")
async def security_middleware(request:Request,call_next):
    enforce_rate_limit(request)
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Cache-Control"]="no-store"
    return response

class ChallengeOut(BaseModel):
    job_id:str; point_id:str; nonce:str; expires_at:float

class AttestationChallengeOut(BaseModel):
    nonce:str; expires_at:float


@app.get("/verify", include_in_schema=False)
def verification_viewer():
    return FileResponse(os.path.join(os.path.dirname(__file__),"..","static","verify.html"))

@app.get("/health")
def health():
    return {"ok": True, "service": "tradedeck-shield", "protocol": "shield-evidence-v1", "api": "1.1"}

@app.get("/shield/v1/health")
def shield_health():
    platforms = enabled_platforms()
    if os.getenv("SHIELD_API_AUTH_MODE") == "local":
        if len(os.getenv("SHIELD_LOCAL_JWT_SECRET","").encode("utf-8")) < 32:
            raise HTTPException(503,"local_jwt_secret_not_configured")
        if os.getenv("SHIELD_AUTHZ_MODE") != "local":
            raise HTTPException(503,"local_job_authorization_not_configured")
    if "ios" in platforms and os.getenv("SHIELD_ATTESTATION_MODE") == "production" and not os.getenv("SHIELD_APP_ID", "").strip():
        raise HTTPException(503,"apple_app_id_not_configured")
    if "android" in platforms and os.getenv("SHIELD_PLAY_INTEGRITY_MODE") == "production":
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

@app.post("/shield/jobs/{job_id}/challenge", response_model=ChallengeOut)
def challenge(request:Request, job_id:str, point_id:str=Form(...), account_id:str|None=Form(None)):
    actor=actor_for(request, account_id)
    account_id=actor.account_id
    try: authorize_job(account_id,job_id,point_id)
    except AuthorizationError as e: raise HTTPException(403,str(e))
    nonce,exp=store.challenge(job_id,point_id,account_id,TTL)
    return {"job_id":job_id,"point_id":point_id,"nonce":nonce,"expires_at":exp}

@app.post("/shield/attest/challenge", response_model=AttestationChallengeOut)
def attestation_challenge(request:Request, account_id:str|None=Form(None)):
    actor=actor_for(request, account_id)
    account_id=actor.account_id
    nonce, exp = store.attestation_challenge(account_id, TTL)
    return {"nonce": nonce, "expires_at": exp}

@app.post("/shield/attest")
def register_attestation(request:Request, account_id:str|None=Form(None), key_id:str=Form(...), nonce:str=Form(...), attestation:str=Form(...)):
    actor=actor_for(request, account_id)
    account_id=actor.account_id
    try:
        store.consume_attestation_challenge(nonce, account_id)
    except ValueError as e:
        raise HTTPException(409, str(e))
    result = att.verify_attestation(attestation, key_id, nonce.encode("utf-8"))
    if result.get("trusted") is not True:
        raise HTTPException(422, result.get("status", "attestation_rejected"))
    try:
            store.save_attestation_key(key_id, account_id, result["public_key_der_b64"], result["environment"], result.get("receipt_b64", ""))
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"trusted": True, "status": "attested", "key_id": key_id, "environment": result["environment"]}

@app.post("/shield/jobs/{job_id}/photos")
async def capture(request:Request, job_id:str,
    point_id:str=Form(...), account_id:str|None=Form(None), nonce:str=Form(...),
    note: str|None=Form(None), location_stated:str|None=Form(None), purpose:str|None=Form(None),
    captured_at:str=Form(...), lat:float|None=Form(None), lng:float|None=Form(None),
    accuracy_m:float|None=Form(None), location_observed_at:str|None=Form(None), mock_flag:bool|None=Form(None),
    expected_lat:float|None=Form(None), expected_lng:float|None=Form(None),
    attestation_key_id:str|None=Form(None), attestation_assertion:str|None=Form(None),
    play_integrity_token:str|None=Form(None), amendment_of:str|None=Form(None),
    photo:UploadFile=File(...)):
    actor=actor_for(request, account_id)
    account_id=actor.account_id
    try: authorization=authorize_job(account_id,job_id,point_id)
    except AuthorizationError as e: raise HTTPException(403,str(e))
    platforms = enabled_platforms()
    if play_integrity_token and "android" not in platforms:
        raise HTTPException(422, "android_capture_disabled")
    if attestation_assertion and "ios" not in platforms:
        raise HTTPException(422, "ios_capture_disabled")
    if photo.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(415,"unsupported_photo_type")
    raw=await photo.read(MAX_PHOTO_BYTES + 1)
    if not raw: raise HTTPException(400,"empty_photo")
    if len(raw) > MAX_PHOTO_BYTES:
        raise HTTPException(413,"photo_too_large")
    # Section 9: testimony is always explicit. GPS, job metadata, and legacy free-form
    # `note` must never be used to invent or substitute the user's attestation sheet.
    try:
        sheet=AttestationSheet.from_user_input(location_stated,purpose)
    except ValueError as e:
        raise HTTPException(422,str(e))
    note_bytes=sheet.canonical_bytes
    photo_sha=sha256_bytes(raw)
    note_sha=sha256_bytes(note_bytes)
    bh=bind_hash(photo_sha,note_sha,job_id,point_id,nonce,account_id)
    # The signed client data is the canonical bind hash UTF-8 bytes; App Attest signs
    # SHA-256(clientData), exactly as Apple specifies.
    client_hash=sha256_bytes(bh.encode("utf-8"))
    att_result=att.verify_assertion(attestation_assertion,client_hash,attestation_key_id,account_id=account_id,commit_counter=False)
    play_result=play.verify(play_integrity_token,bh) if play_integrity_token else {"trusted": False, "status": "missing_play_integrity_token"}
    if os.getenv("SHIELD_ATTESTATION_MODE","development") == "production":
        if att_result.get("trusted") is not True and play_result.get("trusted") is not True:
            raise HTTPException(422, "platform_attestation_required")
    # Play Integrity is required for Android captures, while a valid Apple App
    # Attest assertion is sufficient for iOS. Reject a supplied invalid Play
    # token even when an Apple assertion is also present.
    if os.getenv("SHIELD_PLAY_INTEGRITY_MODE",att_mode) == "production" and play_integrity_token and play_result.get("trusted") is not True:
        raise HTTPException(422, "play_integrity_required")
    # The uploader cannot choose the expected site coordinates. In standalone mode
    # they come from the administrator's job pin; integrations may supply them in
    # the trusted server-to-server authorization response.
    if authorization["source"] == "shield_local":
        from .local_identity import identity
        pin=identity().job_location(job_id)
        trusted_lat,trusted_lng=pin if pin else (None,None)
    else:
        trusted_lat=authorization.get("expected_lat")
        trusted_lng=authorization.get("expected_lng")
    location_result=evaluate_location(lat=lat,lng=lng,accuracy_m=accuracy_m,
      observed_at=location_observed_at,expected_lat=trusted_lat,expected_lng=trusted_lng,
      mock_flag=mock_flag)
    if location_result["verdict"] == "reject":
        raise HTTPException(422, {"code": "location_rejected", "reasons": location_result["reasons"]})
    eid=str(uuid.uuid4()); written=datetime.now(timezone.utc).isoformat()
    try: timestamp_result=timestamp_bind_hash(bh)
    except RuntimeError as e: raise HTTPException(503,str(e))
    try:
        store.accept_capture(raw, attestation_key_id=attestation_key_id,
          attestation_counter=att_result["counter"] if att_result.get("trusted") is True else None,
          amendment_of=amendment_of,
          id=eid,job_id=job_id,point_id=point_id,account_id=account_id,nonce=nonce,
      photo_sha256=photo_sha,note_sha256=note_sha,bind_hash=bh,captured_at=captured_at,written_at=written,
      location_json=json.dumps({"lat":lat,"lng":lng,"accuracy_m":accuracy_m,"observed_at":location_observed_at,"expected_lat":trusted_lat,"expected_lng":trusted_lng,**location_result},sort_keys=True),
      attestation_json=json.dumps({"apple":att_result,"play_integrity":play_result,"trusted_timestamp":timestamp_result},sort_keys=True),
      attestation_sheet_json=sheet.canonical_bytes.decode("utf-8"),
      status="sealed",state="sealed",actor_id=account_id,state_history=["capture_received","verified","sealed"])
    except ValueError as e:
        raise HTTPException(404 if str(e) == "amendment_parent_not_found" else 409, str(e)) from e
    return {"evidence_id":eid,"status":"sealed","photo_sha256":photo_sha,"note_sha256":note_sha,"bind_hash":bh,"written_at":written,"attestation_sheet":sheet.public_dict(),"location":location_result,"attestation":{"apple":att_result,"play_integrity":play_result},"trusted_timestamp":timestamp_result}

@app.get("/shield/evidence/{evidence_id}/state")
def evidence_state(request:Request, evidence_id:str):
    actor=actor_for(request, None)
    row=store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    if row["account_id"] != actor.account_id: raise HTTPException(403,"evidence_access_denied")
    history=[dict(r) for r in store.state_history(evidence_id)]
    return {"evidence_id":evidence_id,"state":row["state"],"status":row["status"],"history":history}

@app.get("/shield/jobs/{job_id}/captures/by-nonce/{nonce}")
def capture_receipt(request: Request, job_id: str, nonce: str):
    """Resolve a lost capture response before retrying with a new nonce."""
    actor = actor_for(request, None)
    with store.db() as c:
        row = c.execute("SELECT * FROM evidence WHERE job_id=? AND nonce=? AND account_id=?",
                        (job_id, nonce, actor.account_id)).fetchone()
    if not row:
        raise HTTPException(404, "capture_receipt_not_found")
    try: authorize_job(actor.account_id, job_id, row["point_id"])
    except AuthorizationError as e: raise HTTPException(403, str(e)) from e
    return {key: row[key] for key in ("id", "status", "photo_sha256", "note_sha256", "bind_hash", "written_at")} | {"evidence_id": row["id"]}

@app.get("/shield/evidence/{evidence_id}/attestation-sheet")
def evidence_testimony(request: Request, evidence_id: str):
    actor = actor_for(request, None)
    row = store.get(evidence_id)
    if not row: raise HTTPException(404, "evidence_not_found")
    if row["account_id"] != actor.account_id: raise HTTPException(403, "evidence_access_denied")
    if not row["attestation_sheet_json"]: raise HTTPException(404, "legacy_testimony_not_retained")
    return {"evidence_id": evidence_id, "attestation_sheet": json.loads(row["attestation_sheet_json"]), "note_sha256": row["note_sha256"]}

@app.get("/shield/evidence/{evidence_id}/verify")
def verify(request:Request, evidence_id:str):
    """Authenticated owner verification using the server-held original."""
    actor=actor_for(request, None)
    row=store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    if row["account_id"] != actor.account_id:
        raise HTTPException(403,"evidence_access_denied")
    original=store.read_original(row["original_path"])
    return verify_record(row, original, state_history=store.state_history(evidence_id), custody_events=store.custody_history(evidence_id))

@app.post("/shield/v1/verify")
async def independent_verify(
    evidence_id:str=Form(...),
    location_stated:str|None=Form(None),
    purpose:str|None=Form(None),
    photo:UploadFile|None=File(None),
):
    """Independent verification by Evidence ID, optionally against supplied bytes/testimony.

    This endpoint intentionally returns verification facts only; it does not expose
    account identity, raw location, attestation payloads, or the stored original.
    """
    row=store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    supplied=None
    if photo is not None:
        supplied=await photo.read(MAX_PHOTO_BYTES + 1)
        if len(supplied) > MAX_PHOTO_BYTES: raise HTTPException(413,"photo_too_large")
        if not supplied: raise HTTPException(400,"empty_photo")
    original=store.read_original(row["original_path"])
    return verify_record(row, original, supplied, location_stated, purpose,
        state_history=store.state_history(evidence_id), custody_events=store.custody_history(evidence_id))



@app.get("/shield/v1/capture-packs")
def capture_packs(): return {"packs":PACKS}

@app.get("/shield/evidence/{evidence_id}/custody")
def custody(request:Request,evidence_id:str):
    actor=actor_for(request,None); row=store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    if row["account_id"]!=actor.account_id: raise HTTPException(403,"evidence_access_denied")
    events=store.custody_history(evidence_id)
    return {"evidence_id":evidence_id,"chain":verify_chain(events),"events":[dict(e) for e in events],"links":[dict(x) for x in store.links(evidence_id)]}

class EvidenceAction(BaseModel):
    reason:str

@app.post("/shield/evidence/{evidence_id}/void")
def void_evidence(request:Request,evidence_id:str,body:EvidenceAction):
    actor=actor_for(request,None); row=store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    if row["account_id"]!=actor.account_id: raise HTTPException(403,"evidence_access_denied")
    reason=body.reason.strip()
    if not reason: raise HTTPException(422,"reason_required")
    try: store.void(evidence_id,actor.account_id,reason)
    except ValueError as e: raise HTTPException(409,str(e))
    return {"evidence_id":evidence_id,"state":"voided","original_preserved":True}

@app.get("/shield/admin/health")
def admin_health(request:Request):
    actor=actor_for(request,None)
    if os.getenv("SHIELD_API_AUTH_MODE","development") == "local":
        if actor.claims.get("role") != "admin": raise HTTPException(403,"admin_required")
        return {"ok":True,"attestation_mode":att_mode,"authz_mode":"local","timestamp_required":os.getenv("SHIELD_TIMESTAMP_REQUIRED","false").lower()=="true"}
    admins={x.strip() for x in os.getenv("SHIELD_ADMIN_ACCOUNT_IDS","").split(",") if x.strip()}
    if actor.account_id not in admins: raise HTTPException(403,"admin_required")
    return {"ok":True,"attestation_mode":att_mode,"authz_mode":os.getenv("SHIELD_AUTHZ_MODE","development"),"timestamp_required":os.getenv("SHIELD_TIMESTAMP_REQUIRED","false").lower()=="true"}
