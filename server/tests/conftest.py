import pytest

from app import local_identity, security


@pytest.fixture(autouse=True)
def _fresh_rate_limit():
    """The rate limiter's counter is module-level state shared by every test client. A test that sends many requests must not
    leave it full for the next test, so it is emptied before and after each one."""
    security._BUCKETS.clear()
    security._LOGIN_FAILURES.clear()
    yield
    security._BUCKETS.clear()
    security._LOGIN_FAILURES.clear()


@pytest.fixture(autouse=True)
def _cheap_password_hashing(monkeypatch):
    """The real scrypt settings take about 0.2 s a hash, and nearly every test makes an account or signs in. Tests use cheap
    settings with the same names (still different from each other, so the upgrade path is exercised); test_password_upgrade.py
    checks the real table and runs a sign-in with it."""
    monkeypatch.setitem(local_identity.KDF_PARAMS, "scrypt-14-8-1", (2**4, 8, 1))
    monkeypatch.setitem(local_identity.KDF_PARAMS, "scrypt-15-8-3", (2**5, 8, 3))
