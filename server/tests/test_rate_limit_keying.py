"""Who the rate limit counts as one caller, and how many wrong passwords one account gets."""
import pytest
from fastapi.testclient import TestClient

from app import security
from app.main import app
from app.local_identity import LocalIdentity


class _Req:
    def __init__(self, xff=None, host="10.0.0.9"):
        self.headers = {"x-forwarded-for": xff} if xff is not None else {}
        self.client = type("C", (), {"host": host})() if host else None


def test_default_ignores_the_forwarded_header(monkeypatch):
    monkeypatch.delenv("SHIELD_TRUSTED_PROXY_HOPS", raising=False)
    assert security.client_key(_Req("1.2.3.4")) == "10.0.0.9"


def test_one_trusted_proxy_uses_the_last_entry(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_HOPS", "1")
    assert security.client_key(_Req("6.6.6.6, 1.2.3.4")) == "1.2.3.4"  # the left entry is the caller's own claim


def test_two_trusted_proxies_use_the_second_from_the_right(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_HOPS", "2")
    assert security.client_key(_Req("6.6.6.6, 1.2.3.4, 172.16.0.1")) == "1.2.3.4"


def test_a_short_or_missing_header_falls_back_to_the_socket_address(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_HOPS", "2")
    assert security.client_key(_Req("1.2.3.4")) == "10.0.0.9"
    assert security.client_key(_Req(None)) == "10.0.0.9"
    assert security.client_key(_Req(None, host=None)) == "unknown"


def test_a_bad_setting_is_treated_as_off(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_HOPS", "two")
    assert security.client_key(_Req("1.2.3.4")) == "10.0.0.9"


def test_callers_behind_one_proxy_get_separate_limits(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("SHIELD_RATE_LIMIT_PER_MINUTE", "2")
    c = TestClient(app, raise_server_exceptions=False)
    for _ in range(2):
        assert c.get("/health", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert c.get("/health", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429
    assert c.get("/health", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200


@pytest.fixture
def local(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", path)
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("SHIELD_RATE_LIMIT_PER_MINUTE", "1000")
    LocalIdentity(path).create_account("who@example.com", "right-password-123", "capturer")
    return TestClient(app, raise_server_exceptions=False)


def _login(c, email, password):
    return c.post("/shield/auth/login", json={"email": email, "password": password})


def test_five_wrong_passwords_lock_that_email_even_for_the_right_one(local):
    for _ in range(5):
        assert _login(local, "who@example.com", "wrong").status_code == 401
    r = _login(local, "who@example.com", "right-password-123")
    assert r.status_code == 429
    assert r.json() == {"detail": "too_many_login_attempts"}
    assert r.headers["retry-after"] == str(security.LOGIN_WINDOW_SECONDS)


def test_the_lock_is_per_email_and_case_insensitive(local):
    for _ in range(5):
        _login(local, "WHO@example.com", "wrong")
    assert _login(local, "who@example.com", "right-password-123").status_code == 429
    assert _login(local, "other@example.com", "wrong").status_code == 401


def test_an_unknown_email_is_throttled_the_same_way(local):
    for _ in range(5):
        assert _login(local, "nobody@example.com", "wrong").status_code == 401
    assert _login(local, "nobody@example.com", "wrong").status_code == 429


def test_a_good_sign_in_clears_the_count(local):
    for _ in range(4):
        _login(local, "who@example.com", "wrong")
    assert _login(local, "who@example.com", "right-password-123").status_code == 200
    for _ in range(4):
        assert _login(local, "who@example.com", "wrong").status_code == 401
    assert _login(local, "who@example.com", "right-password-123").status_code == 200


def test_old_failures_age_out(local, monkeypatch):
    for _ in range(5):
        _login(local, "who@example.com", "wrong")
    monkeypatch.setattr(security, "LOGIN_WINDOW_SECONDS", -1)
    assert _login(local, "who@example.com", "right-password-123").status_code == 200
