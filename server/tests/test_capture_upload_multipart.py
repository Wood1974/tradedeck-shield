"""POST /shield/captures/upload: the photo as raw bytes. Same checks, same reply as the JSON route; the JSON route keeps working."""
import base64
import json

from test_captures import b64, env, photo, Phone  # noqa: F401


def send(env, sealed, data=None, headers=None, meta=None):
    body = {k: v for k, v in sealed.items() if k != "photo_b64"}
    return env.client.post("/shield/captures/upload", data={"meta": json.dumps(body) if meta is None else meta},
                           files={"photo": ("p.jpg", base64.b64decode(sealed["photo_b64"]) if data is None else data, "image/jpeg")},
                           headers=env.alice if headers is None else headers)


def test_stores_the_photo_and_answers_like_the_json_route(env):
    data = photo()
    sealed = env.phone.seal(data)
    via_multipart = send(env, sealed)
    assert via_multipart.status_code == 200
    body = via_multipart.json()
    assert body["already"] is False and body["integrity"] == "verified"
    back = env.client.get(f"/shield/captures/{body['record_hash']}/photo", headers=env.alice)
    assert back.content == data
    again = env.upload(sealed)  # the same photo through the JSON route is the same record
    assert again.status_code == 200 and again.json()["already"] is True
    assert {k: v for k, v in again.json().items() if k != "already"} == {k: v for k, v in body.items() if k != "already"}


def test_twice_is_safe(env):
    sealed = env.phone.seal(photo())
    assert send(env, sealed).json()["already"] is False
    assert send(env, sealed).json()["already"] is True
    assert len(env.client.get("/shield/captures", headers=env.alice).json()["captures"]) == 1


def test_every_refusal_matches_the_json_route(env):
    sealed = env.phone.seal(photo(1))
    assert send(env, sealed, data=photo(2)).json()["detail"] == "photo_hash_mismatch"
    assert send(env, sealed, data=b"").json()["detail"] == "photo_invalid"
    edited = json.loads(json.dumps(sealed)); edited["record"]["wall_time_ms"] += 1
    assert send(env, edited).json()["detail"] == "record_hash_mismatch"
    other = json.loads(json.dumps(sealed)); other["public_key_uncompressed_b64"] = Phone().public_b64
    assert send(env, other).json()["detail"] == "signature_invalid"
    extra = json.loads(json.dumps(sealed)); extra["record"]["caption"] = "later"
    assert send(env, extra).json()["detail"] == "record_invalid"
    assert not any(env.root.rglob("*.jpg"))


def test_bad_meta_is_refused(env):
    sealed = env.phone.seal(photo())
    for bad in ("not json", "[]", "{}", json.dumps({"record": "x"}), "x" * 70_000):
        r = send(env, sealed, meta=bad)
        assert r.status_code == 422 and r.json()["detail"] == "record_invalid", bad[:20]


def test_missing_photo_part_is_refused(env):
    r = env.client.post("/shield/captures/upload", data={"meta": "{}"}, headers=env.alice)
    assert r.status_code == 422


def test_requires_sign_in(env):
    assert send(env, env.phone.seal(photo()), headers={}).status_code in (401, 403)


def test_too_large_is_refused_before_it_is_stored(env, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "MAX_PHOTO_BYTES", 1000)
    r = send(env, env.phone.seal(photo()))
    assert r.status_code == 413 and r.json()["detail"] == "photo_too_large"
    assert env.client.get("/shield/captures", headers=env.alice).json()["captures"] == []


def test_the_quota_applies(env, monkeypatch):
    monkeypatch.setenv("SHIELD_ACCOUNT_QUOTA_MB", "0")
    r = send(env, env.phone.seal(photo()))
    assert r.status_code == 413 and r.json()["detail"] == "quota_exceeded"


def test_another_accounts_upload_is_separate(env):
    bob = env.account("bob@example.com")
    sealed = env.phone.seal(photo())
    assert send(env, sealed).status_code == 200
    assert send(env, sealed, headers=bob).json()["already"] is False
    assert env.client.get("/shield/captures", headers=bob).json()["captures"][0]["record_hash"] == sealed["record"]["record_hash"]


def test_the_phones_cors_preflight_allows_the_multipart_path(env):
    r = env.client.options("/shield/captures/upload", headers={"Origin": "capacitor://localhost", "Access-Control-Request-Method": "POST",
                                                                "Access-Control-Request-Headers": "authorization,content-type"})
    assert r.status_code == 200 and "POST" in r.headers["access-control-allow-methods"]
