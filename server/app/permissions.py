from __future__ import annotations
import os, httpx
class AuthorizationError(Exception): pass

def authorize_job(account_id:str,job_id:str,point_id:str)->dict:
    """Production authorization seam. Uses TradeDeck's server-side authorization endpoint when configured.
    Never accepts a client role claim as authority.
    """
    mode = os.getenv("SHIELD_AUTHZ_MODE", "development")
    if os.getenv("SHIELD_API_AUTH_MODE") == "local" and mode != "local":
        raise AuthorizationError("local_job_authorization_not_configured")
    if mode == "local":
        from .local_identity import identity
        if not identity().allowed(account_id,job_id,point_id):
            raise AuthorizationError("job_access_denied")
        return {"authorized":True,"source":"shield_local"}
    url=os.getenv("TRADEDECK_AUTHZ_URL")
    secret=os.getenv("TRADEDECK_INTERNAL_API_KEY")
    if not url:
        if mode == "production": raise AuthorizationError("job_authorization_not_configured")
        return {"authorized":True,"source":"development"}
    try:
        r=httpx.post(url, json={"account_id":account_id,"job_id":job_id,"point_id":point_id},headers={"Authorization":f"Bearer {secret}"},timeout=5)
        response=r.json()
        if r.status_code!=200 or response.get("authorized") is not True: raise AuthorizationError("job_access_denied")
        # Coordinates are accepted only from the server-to-server authorization response.
        return {"authorized":True,"source":"tradedeck",
                "expected_lat":response.get("expected_lat"),"expected_lng":response.get("expected_lng")}
    except AuthorizationError: raise
    except Exception as e: raise AuthorizationError("job_authorization_unavailable") from e
