"""Going over the rate limit must answer 429 with CORS headers, not a server error the phone shows as "network"."""
import pytest
from fastapi.testclient import TestClient

from app import security
from app.main import app

ORIGIN = "capacitor://localhost"
LIMITED = "/shield/v1/capture-packs"  # a public GET that is rate limited (/health is not)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SHIELD_RATE_LIMIT_PER_MINUTE", "3")
    security._BUCKETS.clear()
    yield TestClient(app, raise_server_exceptions=False)
    security._BUCKETS.clear()


def test_over_the_limit_is_a_429_the_phone_can_read(client):
    for _ in range(3):
        assert client.get(LIMITED, headers={"Origin": ORIGIN}).status_code == 200
    r = client.get(LIMITED, headers={"Origin": ORIGIN})
    assert r.status_code == 429
    assert r.json() == {"detail": "rate_limit_exceeded"}
    assert r.headers.get("access-control-allow-origin") == ORIGIN
    assert r.headers.get("retry-after") == "60"


def test_the_security_headers_are_still_on_normal_answers(client):
    r = client.get(LIMITED)
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_the_limit_is_counted_per_caller_not_globally(client, monkeypatch):
    for _ in range(3):
        client.get(LIMITED)
    assert client.get(LIMITED).status_code == 429
    security._BUCKETS.clear()
    assert client.get(LIMITED).status_code == 200
