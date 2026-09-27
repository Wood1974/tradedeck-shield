from app.custody_chain import event_hash, verify_chain
from app.capture_packs import get_pack
from app.offline import OFFLINE_POLICY
from app.permissions import authorize_job

def test_chain_hash_is_deterministic():
    h=event_hash(None,"sealed","2026-01-01T00:00:00Z","u",{"x":1})
    assert h==event_hash(None,"sealed","2026-01-01T00:00:00Z","u",{"x":1}) and len(h)==64

def test_capture_packs():
    assert get_pack("closeout")["required_points"]

def test_offline_never_seals():
    assert OFFLINE_POLICY["local_sealing"] is False and OFFLINE_POLICY["fresh_nonce_required"] is True

def test_development_authz(monkeypatch):
    monkeypatch.delenv("TRADEDECK_AUTHZ_URL",raising=False); monkeypatch.setenv("SHIELD_AUTHZ_MODE","development")
    assert authorize_job("a","j","p")["authorized"] is True
