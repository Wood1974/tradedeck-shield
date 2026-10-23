"""Forgot-password by emailed one-time code: the whole life of a code, and what must not leak."""
import re
import time

import pytest
from fastapi.testclient import TestClient

from app import password_reset, security
from app.local_identity import LocalIdentity
from app.main import app

EMAIL = "worker@example.com"
OLD = "old-password-12345"
NEW = "brand-new-password-1"


@pytest.fixture
def env(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv("SHIELD_DATABASE_URL", path)
    monkeypatch.setenv("SHIELD_API_AUTH_MODE", "local")
    monkeypatch.setenv("SHIELD_AUTHZ_MODE", "local")
    monkeypatch.setenv("SHIELD_LOCAL_JWT_SECRET", "this-is-a-test-secret-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("RESEND_API_KEY", "re_test_not_a_real_key")
    monkeypatch.setenv("SHIELD_MAIL_FROM", "Shield <onboarding@resend.dev>")
    security._BUCKETS.clear()
    sent = []
    monkeypatch.setattr(password_reset, "send_email", lambda to, subject, text: sent.append((to, subject, text)))
    local = LocalIdentity(path)
    local.create_account(EMAIL, OLD, "capturer")
    client = TestClient(app)

    class E:
        pass

    e = E()
    e.local, e.client, e.sent = local, client, sent
    e.forgot = lambda email=EMAIL: client.post("/shield/auth/forgot", json={"email": email})
    e.reset = lambda code, password=NEW, email=EMAIL: client.post("/shield/auth/reset", json={"email": email, "code": code, "new_password": password})
    e.login = lambda password: client.post("/shield/auth/login", json={"email": EMAIL, "password": password})

    def code():
        return re.search(r"\b(\d{8})\b", sent[-1][2]).group(1)

    e.code = code
    return e


def test_a_code_by_email_sets_a_new_password_and_signs_everyone_out(env):
    old_token = env.login(OLD).json()["access_token"]
    assert env.client.get("/shield/auth/me", headers={"Authorization": "Bearer " + old_token}).status_code == 200
    assert env.forgot().status_code == 200
    to, subject, text = env.sent[-1]
    assert to == EMAIL and "reset code" in subject.lower() and "15 minutes" in text
    assert env.reset(env.code()).status_code == 200
    assert env.login(NEW).status_code == 200
    assert env.login(OLD).status_code == 401
    assert env.client.get("/shield/auth/me", headers={"Authorization": "Bearer " + old_token}).status_code == 401


def test_an_unknown_email_gets_the_identical_answer_and_no_email(env):
    known = env.forgot()
    unknown = env.forgot("nobody@example.com")
    assert (known.status_code, known.json()) == (unknown.status_code, unknown.json()) == (200, {"ok": True})
    assert [m[0] for m in env.sent] == [EMAIL]


def test_the_code_never_comes_back_in_any_response(env):
    r = env.forgot()
    code = env.code()
    assert code not in r.text
    wrong = env.reset("00000000")
    assert code not in wrong.text and wrong.json()["detail"] == "invalid_or_expired_code"


def test_a_code_works_once(env):
    env.forgot()
    code = env.code()
    assert env.reset(code).status_code == 200
    again = env.reset(code, password="another-new-password-2")
    assert again.status_code == 400 and again.json()["detail"] == "invalid_or_expired_code"
    assert env.login(NEW).status_code == 200


def test_five_wrong_tries_kill_the_code_even_for_the_right_one(env):
    env.forgot()
    code = env.code()
    wrong = "00000000" if code != "00000000" else "11111111"
    for _ in range(5):
        assert env.reset(wrong).status_code == 400
    assert env.reset(code).status_code == 400
    assert env.login(OLD).status_code == 200


def test_an_expired_code_is_refused(env):
    env.forgot()
    code = env.code()
    with env.local.db() as db:
        db.execute("UPDATE password_resets SET expires_at=?", (time.time() - 1,))
    assert env.reset(code).json()["detail"] == "invalid_or_expired_code"
    assert env.login(OLD).status_code == 200


def test_a_new_request_replaces_the_old_code(env):
    env.forgot()
    first = env.code()
    env.forgot()
    second = env.code()
    if first != second:
        assert env.reset(first).status_code == 400
    assert env.reset(second).status_code == 200


def test_only_three_requests_an_hour_send_email(env):
    for _ in range(5):
        assert env.forgot().json() == {"ok": True}
    assert len(env.sent) == 3


def test_a_short_new_password_is_refused_without_using_up_the_code(env):
    env.forgot()
    code = env.code()
    short = env.reset(code, password="short")
    assert short.status_code == 422 and short.json()["detail"] == "password_length_invalid"
    assert env.reset(code).status_code == 200


def test_without_an_email_service_it_says_so_and_stores_nothing(env, monkeypatch):
    monkeypatch.delenv("RESEND_API_KEY")
    r = env.forgot()
    assert r.status_code == 503 and r.json()["detail"] == "email_not_configured"
    assert env.sent == []
    assert env.forgot("nobody@example.com").status_code == 503  # says nothing about accounts either


def test_a_failed_send_still_answers_the_same_and_logs_no_code(env, monkeypatch, caplog):
    def boom(to, subject, text):
        raise RuntimeError("mail_send_failed:403:domain not verified")

    monkeypatch.setattr(password_reset, "send_email", boom)
    with caplog.at_level("ERROR"):
        r = env.forgot()
    assert (r.status_code, r.json()) == (200, {"ok": True})
    assert "mail_send_failed" in caplog.text
    with env.local.db() as db:
        stored = db.execute("SELECT code_hash FROM password_resets").fetchone()["code_hash"]
    assert stored not in caplog.text


def test_a_deactivated_account_gets_no_code(env):
    admin = env.local.create_account("boss@example.com", "boss-password-12345", "admin")
    other = env.local.create_account("gone@example.com", "gone-password-12345", "capturer")
    env.local.deactivate(admin, other.id)
    env.sent.clear()
    assert env.forgot("gone@example.com").status_code == 200
    assert env.sent == []


def test_the_real_sender_posts_to_resend_with_the_key_and_from_address(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_test_not_a_real_key")
    monkeypatch.setenv("SHIELD_MAIL_FROM", "Shield <onboarding@resend.dev>")
    calls = []

    class R:
        status_code = 200
        text = "{}"

    monkeypatch.setattr(password_reset.requests, "post", lambda url, **kw: (calls.append((url, kw)), R())[1])
    password_reset.send_email("a@b.test", "Subject", "Body 12345678")
    url, kw = calls[0]
    assert url == "https://api.resend.com/emails"
    assert kw["headers"]["Authorization"] == "Bearer re_test_not_a_real_key"
    assert kw["json"] == {"from": "Shield <onboarding@resend.dev>", "to": ["a@b.test"], "subject": "Subject", "text": "Body 12345678"}
    assert kw["timeout"] == 10
