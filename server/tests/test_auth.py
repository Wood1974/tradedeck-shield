import os
from fastapi import HTTPException
from fastapi.requests import Request
from app.auth import actor_for


def req(headers=None):
    scope={"type":"http","method":"GET","path":"/","headers":[(k.lower().encode(),v.encode()) for k,v in (headers or {}).items()]}
    return Request(scope)


def test_development_accepts_supplied_identity():
    os.environ['SHIELD_API_AUTH_MODE']='development'
    actor=actor_for(req(), 'acct-dev')
    assert actor.account_id == 'acct-dev'


def test_production_requires_bearer():
    os.environ['SHIELD_API_AUTH_MODE']='production'
    try:
        actor_for(req(), 'acct-dev')
        assert False, 'expected authorization failure'
    except HTTPException as exc:
        assert exc.status_code == 401
    finally:
        os.environ['SHIELD_API_AUTH_MODE']='development'
