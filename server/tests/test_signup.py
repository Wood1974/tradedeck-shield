"""Sign-up by single-use invite code: minting, spending, and what must not leak."""
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app import security, signup
from app.local_identity import LocalIdentity
from app.main import app

ADMIN = "admin@example.com"
ADMIN_PW = "admin-password-12345"
NEW_EMAIL = "newperson@example.com"
NEW_PW = "a-long-new-password-1"


@pytest.fixture
def env(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", path)
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    security._BUCKETS.clear()
    local = LocalIdentity(path)
    local.create_account(ADMIN, ADMIN_PW, "admin")
    client = TestClient(app)

    class E:
        pass

    e = E()
    e.local, e.client = local, client
    token = client.post("/shield/auth/login", json={"email": ADMIN, "password": ADMIN_PW}).json()["access_token"]
    e.mint = lambda count=1, days=14, headers=None: client.post(
        "/shield/admin/invites", json={"count": count, "days": days}, headers=headers if headers is not None else {"Authorization": "Bearer " + token})
    e.signup = lambda code, email=NEW_EMAIL, password=NEW_PW: client.post(
        "/shield/auth/signup", json={"email": email, "password": password, "invite_code": code})
    e.login = lambda email=NEW_EMAIL, password=NEW_PW: client.post("/shield/auth/login", json={"email": email, "password": password})
    e.path = path.removeprefix("sqlite:///")
    return e


def test_an_invite_makes_a_capturer_account_that_can_sign_in(env):
    code = env.mint().json()["codes"][0]
    assert env.signup(code).status_code == 200
    login = env.login()
    assert login.status_code == 200 and login.json()["role"] == "capturer"


def test_a_code_works_once(env):
    code = env.mint().json()["codes"][0]
    assert env.signup(code).status_code == 200
    again = env.signup(code, email="other@example.com")
    assert again.status_code == 400 and again.json()["detail"] == "invalid_or_expired_invite"
    assert env.login("other@example.com").status_code == 401


def test_an_unknown_used_or_expired_code_all_read_the_same(env):
    good = env.mint(2).json()["codes"]
    env.signup(good[0])
    with sqlite3.connect(env.path) as db:
        db.execute("UPDATE signup_invites SET expires_at=? WHERE used_at IS NULL", (time.time() - 1,))
    answers = {env.signup(c, email=f"x{i}@example.com").json()["detail"] for i, c in enumerate(["AAAA-BBBB-CCCC", good[0], good[1]])}
    assert answers == {"invalid_or_expired_invite"}


def test_case_spaces_and_dashes_do_not_matter(env):
    code = env.mint().json()["codes"][0]
    assert env.signup(code.lower().replace("-", " ")).status_code == 200


def test_a_code_is_not_spent_when_the_account_cannot_be_made(env):
    code = env.mint().json()["codes"][0]
    short = env.signup(code, password="short")
    assert short.status_code == 422 and short.json()["detail"] == "password_length_invalid"
    bad_email = env.signup(code, email="not-an-email")
    assert bad_email.status_code == 422
    taken = env.signup(code, email=ADMIN)
    assert taken.status_code == 409 and taken.json()["detail"] == "account_already_exists"
    assert env.signup(code).status_code == 200  # still unspent after three failures


def test_two_people_cannot_spend_one_code(env):
    code = env.mint().json()["codes"][0]
    results = []
    for email in ("one@example.com", "two@example.com"):
        results.append(env.signup(code, email=email).status_code)
    assert sorted(results) == [200, 400]


def test_codes_are_stored_hashed_and_never_logged_in_the_row(env):
    code = env.mint().json()["codes"][0]
    with sqlite3.connect(env.path) as db:
        rows = db.execute("SELECT * FROM signup_invites").fetchall()
    assert len(rows) == 1
    assert signup.normalize(code) not in repr(rows) and code not in repr(rows)


def test_only_an_administrator_can_make_codes(env):
    code = env.mint().json()["codes"][0]
    env.signup(code)
    token = env.login().json()["access_token"]
    assert env.mint(headers={"Authorization": "Bearer " + token}).status_code == 403
    assert env.mint(headers={}).status_code in (401, 403)


def test_a_batch_is_limited(env):
    assert env.mint(count=0).status_code == 422
    assert env.mint(count=signup.MAX_BATCH + 1).status_code == 422
    assert env.mint(days=signup.MAX_DAYS + 1).status_code == 422
    assert len(env.mint(count=3).json()["codes"]) == 3


def test_codes_are_distinct_and_use_the_unambiguous_alphabet(env):
    codes = env.mint(count=20).json()["codes"]
    assert len(set(codes)) == 20
    for code in codes:
        plain = signup.normalize(code)
        assert len(plain) == signup.CODE_LENGTH and set(plain) <= set(signup.ALPHABET)


def test_signup_never_makes_an_administrator(env):
    code = env.mint().json()["codes"][0]
    payload = {"email": NEW_EMAIL, "password": NEW_PW, "invite_code": code, "role": "admin"}
    assert env.client.post("/shield/auth/signup", json=payload).status_code == 200
    assert env.login().json()["role"] == "capturer"


def test_signup_is_off_unless_local_accounts_are_on(env, monkeypatch):
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "development")
    assert env.signup("AAAA-BBBB-CCCC").status_code == 404


def test_signup_still_works_after_the_admin_is_gone(env):
    code = env.mint().json()["codes"][0]
    with env.local.db() as db:
        db.execute("UPDATE local_accounts SET active=0 WHERE role='admin'")
    assert env.signup(code).status_code == 200
    assert env.login().status_code == 200
