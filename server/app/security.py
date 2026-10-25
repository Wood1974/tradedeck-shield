from __future__ import annotations
import os,time
from collections import defaultdict,deque
from fastapi import Request,HTTPException
_BUCKETS=defaultdict(deque)
_LOGIN_FAILURES: dict[str, deque] = {}
LOGIN_WINDOW_SECONDS = 15 * 60
_LOGIN_KEYS_MAX = 10_000


def client_key(request: Request) -> str:
    """Who the rate limit counts as one caller.

    Behind a proxy the address the server sees is the proxy's, so every caller would share one bucket. When
    SHIELD_TRUSTED_PROXY_HOPS is N (the number of proxies in front of the app that each append the address they saw to
    X-Forwarded-For), the caller is the Nth entry from the right: entries to its left are whatever the caller claimed and
    are ignored. Unset or 0 (the default) keeps the socket address and never reads the header, so a header cannot be
    used to dodge the limit until an owner has said how many proxies there are."""
    try: hops = int(os.getenv("SHIELD_TRUSTED_PROXY_HOPS", "0") or 0)
    except ValueError: hops = 0
    if hops > 0:
        parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(parts) >= hops: return parts[-hops]
    return request.client.host if request.client else "unknown"


def enforce_rate_limit(request:Request):
    limit=int(os.getenv("SHIELD_RATE_LIMIT_PER_MINUTE","120")); key=client_key(request); now=time.time(); q=_BUCKETS[key]
    while q and q[0]<now-60:q.popleft()
    if len(q)>=limit: raise HTTPException(429,"rate_limit_exceeded")
    q.append(now)


def _login_key(email: str) -> str:
    return (email or "").strip().lower()[:254]


def _recent_failures(key: str, now: float) -> deque:
    q = _LOGIN_FAILURES.get(key)
    if q is None: return deque()
    while q and q[0] < now - LOGIN_WINDOW_SECONDS: q.popleft()
    return q


def login_throttle_check(email: str) -> None:
    """Refuses a sign-in once an email has failed too often lately, whether or not an account has that email, so the
    answer never says which emails exist. The limit above counts callers; this one counts guesses at one account."""
    limit = int(os.getenv("SHIELD_LOGIN_MAX_FAILURES", "5"))
    if len(_recent_failures(_login_key(email), time.time())) >= limit:
        raise HTTPException(429, "too_many_login_attempts", headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)})


def login_failed(email: str) -> None:
    now = time.time(); key = _login_key(email)
    if len(_LOGIN_FAILURES) >= _LOGIN_KEYS_MAX:
        for k in [k for k in _LOGIN_FAILURES if not _recent_failures(k, now)]: _LOGIN_FAILURES.pop(k, None)
        if len(_LOGIN_FAILURES) >= _LOGIN_KEYS_MAX: return
    q = _recent_failures(key, now)
    q.append(now); _LOGIN_FAILURES[key] = q


def login_succeeded(email: str) -> None:
    _LOGIN_FAILURES.pop(_login_key(email), None)
