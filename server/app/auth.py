from __future__ import annotations
import os, time
from dataclasses import dataclass
from typing import Any
import httpx
import jwt
from fastapi import HTTPException, Request

@dataclass(frozen=True)
class Actor:
    account_id: str
    claims: dict[str, Any]

class SupabaseJWTVerifier:
    def __init__(self):
        self.url = os.getenv('SUPABASE_URL', '').rstrip('/')
        self.issuer = os.getenv('SUPABASE_JWT_ISSUER', f'{self.url}/auth/v1' if self.url else '')
        self.jwks_url = os.getenv('SUPABASE_JWKS_URL', f'{self.issuer}/.well-known/jwks.json' if self.issuer else '')
        self.audience = os.getenv('SUPABASE_JWT_AUDIENCE', 'authenticated')
        self.cache_seconds = int(os.getenv('SHIELD_JWKS_CACHE_SECONDS', '600'))
        self._jwks: dict[str, Any] | None = None
        self._loaded_at = 0.0

    def _keys(self) -> dict[str, Any]:
        now = time.time()
        if self._jwks and now - self._loaded_at < self.cache_seconds:
            return self._jwks
        if not self.jwks_url:
            raise HTTPException(503, 'supabase_jwt_not_configured')
        try:
            r = httpx.get(self.jwks_url, timeout=5.0)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict) or not isinstance(data.get('keys'), list):
                raise ValueError('invalid_jwks')
            self._jwks = data
            self._loaded_at = now
            return data
        except Exception as exc:
            if self._jwks:
                return self._jwks
            raise HTTPException(503, 'supabase_jwks_unavailable') from exc

    def verify(self, token: str) -> Actor:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')
            alg = header.get('alg')
            if not kid or alg not in {'RS256', 'ES256', 'ES384', 'ES512'}:
                raise ValueError('unsupported_jwt')
            keys = self._keys()['keys']
            jwk = next((k for k in keys if k.get('kid') == kid), None)
            if not jwk:
                self._jwks = None
                keys = self._keys()['keys']
                jwk = next((k for k in keys if k.get('kid') == kid), None)
            if not jwk:
                raise ValueError('unknown_kid')
            key = jwt.PyJWK(jwk).key
            claims = jwt.decode(token, key, algorithms=[alg], audience=self.audience, issuer=self.issuer,
                                options={'require': ['exp', 'sub', 'iss', 'aud']})
            account_id = claims.get('sub')
            if not isinstance(account_id, str) or not account_id:
                raise ValueError('subject_required')
            return Actor(account_id=account_id, claims=claims)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(401, 'invalid_access_token') from exc

verifier = SupabaseJWTVerifier()

def actor_from_request(request: Request) -> Actor:
    mode = os.getenv('SHIELD_API_AUTH_MODE', 'development').lower()
    auth = request.headers.get('authorization', '')
    if mode == 'local':
        if not auth.startswith('Bearer '):
            raise HTTPException(401, 'authorization_required')
        from .local_identity import identity
        try:
            account = identity().verify(auth[7:].strip())
            return Actor(account_id=account.id, claims={'sub':account.id,'role':account.role,'local':True})
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(401, 'invalid_access_token') from exc
    if not auth.startswith('Bearer '):
        if mode == 'production':
            raise HTTPException(401, 'authorization_required')
        account_id = request.headers.get('x-shield-account-id')
        if not account_id:
            raise HTTPException(401, 'authorization_required')
        return Actor(account_id=account_id, claims={'sub': account_id, 'development': True})
    return verifier.verify(auth[7:].strip())

def actor_for(request: Request, supplied_account_id: str | None) -> Actor:
    mode = os.getenv('SHIELD_API_AUTH_MODE', 'development').lower()
    if mode == 'local':
        actor = actor_from_request(request)
        if supplied_account_id and supplied_account_id != actor.account_id:
            raise HTTPException(403, 'account_context_mismatch')
        return actor
    auth = request.headers.get('authorization', '')
    if auth.startswith('Bearer '):
        actor = verifier.verify(auth[7:].strip())
        if supplied_account_id and mode == 'production' and supplied_account_id != actor.account_id:
            raise HTTPException(403, 'account_context_mismatch')
        return actor
    if mode == 'production':
        raise HTTPException(401, 'authorization_required')
    if supplied_account_id:
        return Actor(account_id=supplied_account_id, claims={'sub': supplied_account_id, 'development': True})
    return actor_from_request(request)
