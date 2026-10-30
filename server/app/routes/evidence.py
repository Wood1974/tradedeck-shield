from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel

from .. import attestation_evidence
from ..attestation_sheet import AttestationSheet
from ..auth import actor_for
from ..capture_packs import PACKS
from ..custody_chain import verify_chain
from ..location import evaluate_location
from ..permissions import authorize_job, AuthorizationError
from ..protocol import sha256_bytes, bind_hash
from ..timestamping import timestamp_bind_hash
from ..verification import verify_record

router = APIRouter()


def _m():
    # main.py owns the shared store and attestation verifiers; tests patch them there, so read them when a request arrives.
    from .. import main
    return main

class ChallengeOut(BaseModel):
    job_id:str; point_id:str; nonce:str; expires_at:float

class AttestationChallengeOut(BaseModel):
    nonce:str; expires_at:float



@router.post("/shield/jobs/{job_id}/challenge", response_model=ChallengeOut)
def challenge(request:Request, job_id:str, point_id:str=Form(...), account_id:str|None=Form(None)):
    actor=actor_for(request, account_id)
    account_id=actor.account_id
    try: authorize_job(account_id,job_id,point_id)
    except AuthorizationError as e: raise HTTPException(403,str(e))
    nonce,exp=_m().store.challenge(job_id,point_id,account_id,_m().TTL)
    return {"job_id":job_id,"point_id":point_id,"nonce":nonce,"expires_at":exp}

@router.post("/shield/attest/challenge", response_model=AttestationChallengeOut)
def attestation_challenge(request:Request, account_id:str|None=Form(None)):
    actor=actor_for(request, account_id)
    account_id=actor.account_id
    nonce, exp = _m().store.attestation_challenge(account_id, _m().TTL)
    return {"nonce": nonce, "expires_at": exp}

@router.post("/shield/attest")
def register_attestation(request:Request, account_id:str|None=Form(None), key_id:str=Form(...), nonce:str=Form(...), attestation:str=Form(...)):
    actor=actor_for(request, account_id)
    account_id=actor.account_id
    try:
        _m().store.consume_attestation_challenge(nonce, account_id)
    except ValueError as e:
        raise HTTPException(409, str(e))
    result = _m().att.verify_attestation(attestation, key_id, nonce.encode("utf-8"))
    if result.get("trusted") is not True:
        raise HTTPException(422, result.get("status", "attestation_rejected"))
    try:
            _m().store.save_attestation_key(key_id, account_id, result["public_key_der_b64"], result["environment"], result.get("receipt_b64", ""))
            # Keep what Apple signed, not only the verdict, so it can be checked without this server (attestation_evidence.py).
            attestation_evidence.save(_m().store, key_id, account_id, attestation, nonce, _m().att.app_id, result["environment"])
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"trusted": True, "status": "attested", "key_id": key_id, "environment": result["environment"]}

@router.post("/shield/jobs/{job_id}/photos")
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
    try: authorize_job(account_id,job_id,point_id)
    except AuthorizationError as e: raise HTTPException(403,str(e))
    if photo.content_type not in _m().ALLOWED_IMAGE_TYPES:
        raise HTTPException(415,"unsupported_photo_type")
    raw=await photo.read(_m().MAX_PHOTO_BYTES + 1)
    if not raw: raise HTTPException(400,"empty_photo")
    if len(raw) > _m().MAX_PHOTO_BYTES:
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
    att_result=_m().att.verify_assertion(attestation_assertion,client_hash,attestation_key_id,account_id=account_id,commit_counter=False)
    play_result=_m().play.verify(play_integrity_token,bh) if play_integrity_token else {"trusted": False, "status": "missing_play_integrity_token"}
    if os.getenv("SHIELD_ATTESTATION_MODE","development") == "production":
        if att_result.get("trusted") is not True and play_result.get("trusted") is not True:
            raise HTTPException(422, "platform_attestation_required")
    # Play Integrity is required for Android captures, while a valid Apple App
    # Attest assertion is sufficient for iOS. Reject a supplied invalid Play
    # token even when an Apple assertion is also present.
    if os.getenv("SHIELD_PLAY_INTEGRITY_MODE",_m().att_mode) == "production" and play_integrity_token and play_result.get("trusted") is not True:
        raise HTTPException(422, "play_integrity_required")
    try: _m().store.consume(nonce,job_id,point_id,account_id)
    except ValueError as e: raise HTTPException(409,str(e))
    if att_result.get("trusted") is True and _m().att.update_counter(attestation_key_id, att_result["counter"]) is False:
        raise HTTPException(409,"attestation_counter_update_failed")
    # Location is a risk signal, never proof of physical presence. Section 13 will
    # replace client-supplied expected coordinates with authoritative TradeDeck job data.
    location_result=evaluate_location(lat=lat,lng=lng,accuracy_m=accuracy_m,
      observed_at=location_observed_at,expected_lat=expected_lat,expected_lng=expected_lng,
      mock_flag=mock_flag)
    verdict=location_result["verdict"]; reasons=location_result["reasons"]
    eid=str(uuid.uuid4()); written=datetime.now(timezone.utc).isoformat()
    try: timestamp_result=timestamp_bind_hash(bh)
    except RuntimeError as e: raise HTTPException(503,str(e))
    rel=_m().store.save_original(eid,job_id,account_id,raw)
    _m().store.create_evidence(id=eid,job_id=job_id,point_id=point_id,account_id=account_id,nonce=nonce,
      photo_sha256=photo_sha,note_sha256=note_sha,bind_hash=bh,captured_at=captured_at,written_at=written,
      location_json=json.dumps({"lat":lat,"lng":lng,"accuracy_m":accuracy_m,"observed_at":location_observed_at,"expected_lat":expected_lat,"expected_lng":expected_lng,**location_result},sort_keys=True),
      attestation_json=json.dumps({"apple":att_result,"play_integrity":play_result,"trusted_timestamp":timestamp_result},sort_keys=True),original_path=rel,status="sealed",state="sealed",actor_id=account_id,state_history=["capture_received","verified","sealed"])
    if amendment_of:
        parent=_m().store.get(amendment_of)
        if not parent or parent["account_id"]!=account_id: raise HTTPException(404,"amendment_parent_not_found")
        if parent["state"]!="sealed": raise HTTPException(409,"amendment_parent_not_sealed")
        _m().store.link_evidence(amendment_of,eid,"amendment",written)
        _m().store.transition_state(amendment_of,"amended",account_id,{"child_evidence_id":eid})
        _m().store.append_custody_event(amendment_of,"amended",written,account_id,{"child_evidence_id":eid})
    return {"evidence_id":eid,"status":"sealed","photo_sha256":photo_sha,"note_sha256":note_sha,"bind_hash":bh,"written_at":written,"attestation_sheet":sheet.public_dict(),"location":location_result,"attestation":{"apple":att_result,"play_integrity":play_result},"trusted_timestamp":timestamp_result}

@router.get("/shield/evidence/{evidence_id}/state")
def evidence_state(request:Request, evidence_id:str):
    actor=actor_for(request, None)
    row=_m().store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    if row["account_id"] != actor.account_id: raise HTTPException(403,"evidence_access_denied")
    history=[dict(r) for r in _m().store.state_history(evidence_id)]
    return {"evidence_id":evidence_id,"state":row["state"],"status":row["status"],"history":history}

@router.get("/shield/evidence/{evidence_id}/verify")
def verify(request:Request, evidence_id:str):
    """Authenticated owner verification using the server-held original."""
    actor=actor_for(request, None)
    row=_m().store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    if row["account_id"] != actor.account_id:
        raise HTTPException(403,"evidence_access_denied")
    path=_m().store.root/row["original_path"]
    original=path.read_bytes() if path.exists() else None
    return verify_record(row, original, state_history=_m().store.state_history(evidence_id), custody_events=_m().store.custody_history(evidence_id))

@router.post("/shield/v1/verify")
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
    row=_m().store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    supplied=None
    if photo is not None:
        supplied=await photo.read(_m().MAX_PHOTO_BYTES + 1)
        if len(supplied) > _m().MAX_PHOTO_BYTES: raise HTTPException(413,"photo_too_large")
        if not supplied: raise HTTPException(400,"empty_photo")
    path=_m().store.root/row["original_path"]
    original=path.read_bytes() if path.exists() else None
    return verify_record(row, original, supplied, location_stated, purpose,
        state_history=_m().store.state_history(evidence_id), custody_events=_m().store.custody_history(evidence_id))



@router.get("/shield/v1/capture-packs")
def capture_packs(): return {"packs":PACKS}

@router.get("/shield/evidence/{evidence_id}/custody")
def custody(request:Request,evidence_id:str):
    actor=actor_for(request,None); row=_m().store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    if row["account_id"]!=actor.account_id: raise HTTPException(403,"evidence_access_denied")
    events=_m().store.custody_history(evidence_id)
    return {"evidence_id":evidence_id,"chain":verify_chain(events),"events":[dict(e) for e in events],"links":[dict(x) for x in _m().store.links(evidence_id)]}

class EvidenceAction(BaseModel):
    reason:str

@router.post("/shield/evidence/{evidence_id}/void")
def void_evidence(request:Request,evidence_id:str,body:EvidenceAction):
    actor=actor_for(request,None); row=_m().store.get(evidence_id)
    if not row: raise HTTPException(404,"evidence_not_found")
    if row["account_id"]!=actor.account_id: raise HTTPException(403,"evidence_access_denied")
    reason=body.reason.strip()
    if not reason: raise HTTPException(422,"reason_required")
    try: _m().store.transition_state(evidence_id,"voided",actor.account_id,{"reason":reason})
    except ValueError as e: raise HTTPException(409,str(e))
    now=datetime.now(timezone.utc).isoformat(); _m().store.append_custody_event(evidence_id,"voided",now,actor.account_id,{"reason":reason})
    return {"evidence_id":evidence_id,"state":"voided","original_preserved":True}
