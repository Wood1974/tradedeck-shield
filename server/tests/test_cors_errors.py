"""An unhandled server error must still carry CORS headers, or the phone's web view hides it behind a network error."""
from fastapi.testclient import TestClient

from app.main import app

ORIGIN = "capacitor://localhost"


def _boom():
    raise RuntimeError("secret detail that must not reach the client")


def test_unhandled_error_is_json_and_carries_cors_headers():
    app.add_api_route("/__test_boom", _boom, methods=["GET"])
    client = TestClient(app)
    r = client.get("/__test_boom", headers={"Origin": ORIGIN})
    assert r.status_code == 500
    assert r.json() == {"error": "internal_error"}
    assert r.headers.get("access-control-allow-origin") == ORIGIN
    assert "secret detail" not in r.text


def test_other_origins_still_get_no_cors_header_on_errors():
    app.add_api_route("/__test_boom2", _boom, methods=["GET"])
    r = TestClient(app).get("/__test_boom2", headers={"Origin": "https://evil.example"})
    assert r.status_code == 500
    assert "access-control-allow-origin" not in r.headers
