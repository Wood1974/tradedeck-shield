from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ._common import local_account_id

router = APIRouter()

class TicketRequest(BaseModel):
    ticket_id: str

class TicketCountersign(BaseModel):
    ticket: dict
    server_signature_der_b64: str
    ticket_clock: dict
    signature_der_b64: str
    public_key_uncompressed_b64: str

@router.get("/shield/tickets/key")
def ticket_key():
    from .. import tickets
    try: return tickets.public_info()
    except tickets.TicketsClosed as exc: raise HTTPException(503,str(exc)) from exc

@router.post("/shield/tickets")
def issue_ticket(request:Request,body:TicketRequest):
    account_id=local_account_id(request)
    from .. import tickets
    try: return tickets.issue(account_id,body.ticket_id)
    except tickets.TicketsClosed as exc: raise HTTPException(503,str(exc)) from exc
    except tickets.Refused as exc: raise HTTPException(422,str(exc)) from exc

@router.post("/shield/tickets/countersign")
def countersign_ticket(request:Request,body:TicketCountersign):
    account_id=local_account_id(request)
    from .. import tickets
    from ..local_identity import identity
    try: return tickets.countersign(identity(),account_id,body.model_dump())
    except tickets.TicketsClosed as exc: raise HTTPException(503,str(exc)) from exc
    except tickets.Refused as exc: raise HTTPException(409 if str(exc)=="ticket_already_started" else 422,str(exc)) from exc
