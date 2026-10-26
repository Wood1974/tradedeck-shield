"""A share code can be withdrawn with POST, which the phone app is allowed to send; DELETE keeps working."""
from test_captures import env, photo  # noqa: F401
from test_shares import _fresh_limit, check, make_share, stored  # noqa: F401  (autouse fixture and helpers)


def test_post_withdraws_a_code_the_same_way_delete_does(env):
    rh, data = stored(env)
    made = make_share(env, rh).json()
    assert check(env, made["code"], data).status_code == 200
    assert env.client.post(f"/shield/shares/{made['id']}/revoke", headers=env.alice).status_code == 200
    assert check(env, made["code"], data).status_code == 404
    assert env.client.post(f"/shield/shares/{made['id']}/revoke", headers=env.alice).status_code == 404


def test_only_the_owner_can_withdraw_by_post(env):
    rh, _ = stored(env)
    made = make_share(env, rh).json()
    assert env.client.post(f"/shield/shares/{made['id']}/revoke").status_code in (401, 403)
    assert env.client.post(f"/shield/shares/{made['id']}/revoke", headers=env.bob if hasattr(env, "bob") else {"Authorization": "Bearer x"}).status_code in (401, 403, 404)
    assert make_share(env, rh).status_code == 200  # still alice's, still working


def test_the_phones_cors_preflight_allows_post_to_the_revoke_path(env):
    r = env.client.options("/shield/shares/abc/revoke", headers={"Origin": "capacitor://localhost", "Access-Control-Request-Method": "POST",
                                                                  "Access-Control-Request-Headers": "authorization,content-type"})
    assert r.status_code == 200 and "POST" in r.headers["access-control-allow-methods"]
