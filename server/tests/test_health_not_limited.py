"""Render's health check must never use up anyone's rate limit, and must keep answering however busy the caller has been."""
import pytest
from fastapi.testclient import TestClient

from app import security
from app.main import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SHIELD_RATE_LIMIT_PER_MINUTE", "3")
    return TestClient(app, raise_server_exceptions=False)


def test_health_checks_are_not_counted(client):
    for _ in range(50):
        assert client.get("/health").status_code == 200
    assert client.get("/shield/v1/capture-packs").status_code == 200  # the caller's own allowance is untouched
    assert not security._BUCKETS or sum(len(q) for q in security._BUCKETS.values()) == 1


def test_a_caller_over_the_limit_still_gets_a_health_answer(client):
    for _ in range(3):
        assert client.get("/shield/v1/capture-packs").status_code == 200
    assert client.get("/shield/v1/capture-packs").status_code == 429
    assert client.get("/health").status_code == 200


def test_only_the_plain_health_path_is_exempt():
    assert security.UNLIMITED_PATHS == frozenset({"/health"})
