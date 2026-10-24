from __future__ import annotations

import os

from fastapi import HTTPException, Request

from ..auth import actor_for


def local_account_id(request: Request) -> str:
    """The signed-in account for a route that is only open in standalone (local) mode."""
    if os.getenv("SHIELD_API_AUTH_MODE", "development") != "local":
        raise HTTPException(404, "local_identity_disabled")
    return actor_for(request, None).account_id
