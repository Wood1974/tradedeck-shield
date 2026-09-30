"""Keep API tests independent of previous runs and production environment values."""
import importlib
import pytest
from app.store import Store
from app.security import _BUCKETS

@pytest.fixture(autouse=True)
def isolated_api(monkeypatch, tmp_path):
    main = importlib.import_module("app.main")
    for key in ("SHIELD_API_AUTH_MODE", "SHIELD_AUTHZ_MODE", "SHIELD_ATTESTATION_MODE", "SHIELD_PLAY_INTEGRITY_MODE"):
        monkeypatch.setenv(key, "development")
    monkeypatch.setenv("SHIELD_ENABLED_PLATFORMS", "ios,android")
    monkeypatch.setenv("SHIELD_TIMESTAMP_REQUIRED", "false")
    monkeypatch.delenv("SHIELD_RFC3161_GATEWAY_URL", raising=False)
    st = Store(f"sqlite:///{tmp_path / 'api.db'}", str(tmp_path / 'api-storage'))
    monkeypatch.setattr(main, "store", st)
    monkeypatch.setattr(main.att, "store", st)
    _BUCKETS.clear()
    yield
    _BUCKETS.clear()
