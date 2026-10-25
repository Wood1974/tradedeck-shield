"""Random damage to an upload must never crash the server, and nothing damaged may be stored as if it were good.

Every upload that the server does accept is also run through the independent verifier (verifier/shield_verify.py,
written from docs/RECORD_SPEC.md). The two must agree: a record the server stores that the verifier rejects, or the
other way round, is a bug in one of them. Seeded, so a failure repeats; SHIELD_FUZZ_ROUNDS and SHIELD_FUZZ_SEED change that
(the nightly job runs many more rounds with a fresh seed and prints it).
"""
import base64
import copy
import importlib.util
import json
import os
import random
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import security
from app.local_identity import LocalIdentity
from app.main import app
from test_captures import PW, Phone, photo

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("shield_verify", ROOT / "verifier" / "shield_verify.py")
sv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv)

ROUNDS = int(os.getenv("SHIELD_FUZZ_ROUNDS", "300"))
SEED = int(os.getenv("SHIELD_FUZZ_SEED", "20261021"))


@pytest.fixture
def env(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", path)
    monkeypatch.setenv("SHIELD_STORAGE_ROOT", str(tmp_path / "storage"))
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("SHIELD_RATE_LIMIT_PER_MINUTE", "1000000")  # these runs send thousands of requests; the limiter has its own test
    security._BUCKETS.clear()
    local = LocalIdentity(path)
    # A server error must come back as a 500 so the test can say so, not be raised into the test.
    client = TestClient(app, raise_server_exceptions=False)

    def account(email):
        local.create_account(email, PW, "capturer")
        token = client.post("/shield/auth/login", json={"email": email, "password": PW}).json()["access_token"]
        return {"Authorization": "Bearer " + token}

    class E:
        pass

    e = E()
    e.client, e.account = client, account
    e.alice = account("alice@example.com")
    e.bob = account("bob@example.com")
    return e


ODD = [None, True, False, 0, -1, 1.5, 2 ** 53, 2 ** 80, "", "x", "A" * 64, "a" * 63, "a" * 65, [], {}, [1], {"a": 1}, "café", "\u0000", "a" * 600]


def mutate(body: dict, rng: random.Random) -> dict:
    b = copy.deepcopy(body)
    kind = rng.randrange(8)
    record = b["record"]
    if kind == 0:   # a record field becomes something odd
        record[rng.choice(list(record))] = rng.choice(ODD)
    elif kind == 1:  # a record field disappears
        record.pop(rng.choice(list(record)))
    elif kind == 2:  # an unknown field appears
        record["extra_" + str(rng.randrange(9))] = rng.choice(ODD)
    elif kind == 3:  # a top-level field becomes something odd or disappears
        key = rng.choice(["signature_der_b64", "public_key_uncompressed_b64", "photo_b64", "app_attest_key_id", "app_attest_assertion_b64"])
        if rng.random() < 0.5:
            b[key] = rng.choice(ODD)
        else:
            b.pop(key, None)
    elif kind == 4:  # one character of the photo changes
        raw = list(b["photo_b64"])
        i = rng.randrange(len(raw))
        raw[i] = rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=!")
        b["photo_b64"] = "".join(raw)
    elif kind == 5:  # one character of a hash or signature changes
        key = rng.choice(["signature_der_b64", "public_key_uncompressed_b64"])
        raw = list(b[key])
        raw[rng.randrange(len(raw))] = rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        b[key] = "".join(raw)
    elif kind == 6:  # the record swaps for a whole other value
        b["record"] = rng.choice(ODD)
    else:            # the whole body is something else
        return rng.choice(ODD) if rng.random() < 0.5 else {k: rng.choice(ODD) for k in b}
    return b


def test_damaged_uploads_never_crash_and_what_is_stored_passes_the_independent_verifier(env):
    rng = random.Random(SEED)
    phone = Phone()
    stored = 0
    for n in range(ROUNDS):
        good = phone.seal(photo(n % 5 + 1), wall_time_ms=1_700_000_000_000 + n)
        phone.prev = good["record"]["prev_hash"] if n % 7 else phone.prev  # now and then re-use a link: forks must not break anything
        body = mutate(good, rng) if rng.random() < 0.9 else good
        resp = env.client.post("/shield/captures", content=json.dumps(body), headers={**env.alice, "Content-Type": "application/json"})
        assert resp.status_code < 500, f"round {n} seed {SEED}: server error {resp.status_code} for {json.dumps(body)[:300]}"
        if resp.status_code == 200 and not resp.json().get("already"):
            stored += 1
            rows = sv.check_item(body, None)
            bad = [r for r in rows if r[1] != "pass"]
            assert not bad, f"round {n} seed {SEED}: the server stored a record the verifier rejects: {bad}"
    assert stored > 0  # the undamaged uploads went through, so the run exercised the success path too


def test_damaged_bodies_that_are_not_even_json_do_not_crash(env):
    rng = random.Random(SEED + 1)
    for n in range(min(ROUNDS, 200)):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        resp = env.client.post("/shield/captures", content=blob, headers={**env.alice, "Content-Type": "application/json"})
        assert resp.status_code < 500, f"round {n} seed {SEED + 1}: server error {resp.status_code}"


def test_nothing_one_account_uploads_is_visible_to_another_however_the_requests_are_shaped(env):
    rng = random.Random(SEED + 2)
    phone = Phone()
    hashes = []
    for n in range(10):
        item = phone.seal(photo(n + 1), wall_time_ms=1_700_000_000_000 + n)
        assert env.client.post("/shield/captures", json=item, headers=env.alice).status_code == 200
        hashes.append(item["record"]["record_hash"])
    assert env.client.get("/shield/captures", headers=env.bob).json()["captures"] == []
    for h in hashes:
        assert env.client.get(f"/shield/captures/{h}/photo", headers=env.bob).status_code == 404
    for _ in range(100):
        guess = "".join(rng.choice("0123456789abcdef") for _ in range(64))
        assert env.client.get(f"/shield/captures/{guess}/photo", headers=env.bob).status_code in (404, 422)
        junk = "".join(rng.choice("abc/.%0\\ ") for _ in range(rng.randrange(1, 70)))
        assert env.client.get(f"/shield/captures/{junk}/photo", headers=env.bob).status_code < 500
    # Bob uploading the same bytes gets his own copy, and Alice still sees only hers.
    assert env.client.post("/shield/captures", json=item, headers=env.bob).status_code == 200
    assert len(env.client.get("/shield/captures", headers=env.alice).json()["captures"]) == 10
    assert len(env.client.get("/shield/captures", headers=env.bob).json()["captures"]) == 1
