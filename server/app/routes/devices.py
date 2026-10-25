from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..security import enforce_rate_limit
from ._common import local_account_id

router = APIRouter()


class RevokeRequest(BaseModel):
    id: str


def _m():
    # main.py owns the shared store; read it when a request arrives.
    from .. import main
    return main


def _iso(seconds):
    from datetime import datetime, timezone
    return None if seconds is None else datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


@router.get("/shield/devices")
def list_devices(request: Request):
    """The phones this account has enrolled with Apple App Attest. Only the account's own; nothing about other accounts."""
    account_id = local_account_id(request)
    from .. import captures
    from ..local_identity import identity
    keys = _m().store.list_attestation_keys(account_id)
    photos = captures.photos_per_phone_key(identity(), account_id)
    return {"devices": [{"id": k["key_id"], "environment": k["environment"], "enrolled_at": _iso(k["created_at"]), "photos": photos.get(k["key_id"], 0),
                         "revoked_at": _iso(k["revoked_at"])} for k in keys]}


# POST as well as DELETE: the phone app's web view is only allowed to send GET and POST across origins (CORS in main.py).
@router.post("/shield/devices/revoke")
def revoke_device(request: Request, body: RevokeRequest):
    """Withdraw a phone's App Attest key. Later photos from it are no longer reported as Apple-checked; photos already stored keep what was recorded."""
    account_id = local_account_id(request)
    enforce_rate_limit(request)
    if not body.id or len(body.id) > 128:
        raise HTTPException(422, "id_required")
    if not _m().store.revoke_attestation_key(body.id, account_id):
        raise HTTPException(404, "not_found")
    return {"ok": True}
