from __future__ import annotations
import logging, os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .store import Store
from .attestation import AttestationVerifier
from .play_integrity import PlayIntegrityVerifier
from .security import enforce_rate_limit
from .identity_api import router as identity_router

app=FastAPI(title="TradeDeck Shield Evidence API", version="2.0.0", docs_url="/docs" if os.getenv("SHIELD_ENABLE_DOCS","false").lower()=="true" else None, redoc_url=None)
MAX_PHOTO_BYTES=int(os.getenv("SHIELD_MAX_PHOTO_BYTES","15728640"))
ALLOWED_IMAGE_TYPES={"image/jpeg","image/jpg"}
store=Store(os.getenv("SHIELD_DATABASE_URL","sqlite:///./shield.db"), os.getenv("SHIELD_STORAGE_ROOT","./storage"))
att_mode=os.getenv("SHIELD_ATTESTATION_MODE","development")
att=AttestationVerifier(att_mode,os.getenv("SHIELD_APP_ID",""),store=store)
play=PlayIntegrityVerifier(os.getenv("SHIELD_PLAY_INTEGRITY_MODE",att_mode),os.getenv("SHIELD_PLAY_PACKAGE_NAME", "app.tradedeck.shield"))
TTL=int(os.getenv("SHIELD_CHALLENGE_TTL_SECONDS","120"))
app.include_router(identity_router)
from .routes import include_all
include_all(app)
@app.middleware("http")
async def _json_500(request, call_next):
    # Registered before CORS so it sits inside it. An unhandled error then leaves as a normal JSON response that CORS
    # decorates; left to the server-error layer it would carry no CORS headers and the phone would only say "network".
    try:
        return await call_next(request)
    except Exception:
        logging.getLogger(__name__).exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse({"error": "internal_error"}, status_code=500)

# The phone app's web view calls this API from its own origin (iOS capacitor://localhost, Android https://localhost).
# Without these the browser blocks the request at the preflight. Bearer tokens, not cookies, so no credentials mode.
app.add_middleware(CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("SHIELD_CORS_ORIGINS","capacitor://localhost,https://localhost").split(",") if o.strip()],
    allow_methods=["GET","POST","OPTIONS"], allow_headers=["Authorization","Content-Type"], max_age=600)

@app.on_event("startup")
def _start_outside_time():
    # Off unless SHIELD_TSA_ENABLED=true. Never delays startup or uploads.
    from . import outside_time
    if outside_time.enabled() and os.getenv("SHIELD_API_AUTH_MODE","development") == "local":
        from .local_identity import identity
        outside_time.start_daily(identity())

@app.on_event("startup")
def _bootstrap_first_admin():
    # A host with no shell has no other way to make the first account. Does nothing once any admin exists.
    if os.getenv("SHIELD_API_AUTH_MODE","development") == "local":
        from .local_identity import ensure_bootstrap_admin
        try:
            if ensure_bootstrap_admin(): logging.getLogger(__name__).warning("Created the first Shield administrator from the bootstrap variables; remove them now")
        except (ValueError, RuntimeError):
            logging.getLogger(__name__).exception("Bootstrap administrator could not be created")


@app.middleware("http")
async def security_middleware(request:Request,call_next):
    enforce_rate_limit(request)
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Cache-Control"]="no-store"
    return response

