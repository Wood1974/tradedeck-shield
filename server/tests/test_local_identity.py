from fastapi.testclient import TestClient
from app.main import app
from app.local_identity import LocalIdentity


def setup_local(monkeypatch, tmp_path):
    path = f"sqlite:///{tmp_path / 'shield.db'}"
    monkeypatch.setenv('SHIELD_DATABASE_URL', path)
    monkeypatch.setenv('SHIELD_API_AUTH_MODE', 'local')
    monkeypatch.setenv('SHIELD_AUTHZ_MODE', 'local')
    monkeypatch.setenv('SHIELD_LOCAL_JWT_SECRET', 'this-is-a-test-secret-with-at-least-thirty-two-bytes')
    local = LocalIdentity(path)
    admin = local.create_account('admin@example.com', 'admin-password-123', 'admin')
    return local,admin,TestClient(app)


def login(client, email, password):
    return client.post('/shield/auth/login',json={'email':email,'password':password})


def test_local_accounts_and_job_grants(monkeypatch,tmp_path):
    local,admin,client=setup_local(monkeypatch,tmp_path)
    assert login(client,'admin@example.com','wrong-password').status_code==401
    signed=login(client,'ADMIN@example.com','admin-password-123')
    assert signed.status_code==200
    admin_header={'Authorization':'Bearer '+signed.json()['access_token']}
    assert client.get('/shield/admin/health',headers=admin_header).status_code==200

    created=client.post('/shield/admin/accounts',json={'email':'worker@example.com','password':'worker-password-123'},headers=admin_header)
    assert created.status_code==200
    worker_id=created.json()['account_id']
    worker=login(client,'worker@example.com','worker-password-123')
    worker_header={'Authorization':'Bearer '+worker.json()['access_token']}
    assert client.post('/shield/admin/accounts',json={'email':'other@example.com','password':'other-password-123'},headers=worker_header).status_code==403

    job={'account_id':worker_id,'job_id':'job-one','point_id':'point-one'}
    assert client.post('/shield/jobs/job-one/challenge',data={'point_id':'point-one'},headers=worker_header).status_code==403
    assert client.post('/shield/admin/job-grants',json=job,headers=admin_header).status_code==200
    assert client.get('/shield/jobs',headers=worker_header).json()=={'jobs':[{'job_id':'job-one','point_id':'point-one'}]}
    assert client.post('/shield/jobs/job-one/challenge',data={'point_id':'point-one'},headers=worker_header).status_code==200
    assert client.post('/shield/jobs/job-one/challenge',data={'point_id':'point-two'},headers=worker_header).status_code==403
    assert client.post('/shield/jobs/job-one/challenge',data={'point_id':'point-one','account_id':admin.id},headers=worker_header).status_code==403

    assert client.request('DELETE','/shield/admin/job-grants',json=job,headers=admin_header).status_code==200
    assert client.post('/shield/jobs/job-one/challenge',data={'point_id':'point-one'},headers=worker_header).status_code==403
    assert client.post(f'/shield/admin/accounts/{worker_id}/reset-password',json={'password':'a-different-password-123'},headers=admin_header).status_code==200
    assert client.get('/shield/auth/me',headers=worker_header).status_code==401
    assert login(client,'worker@example.com','worker-password-123').status_code==401
    worker=login(client,'worker@example.com','a-different-password-123')
    assert worker.status_code==200
    worker_header={'Authorization':'Bearer '+worker.json()['access_token']}
    assert client.post(f'/shield/admin/accounts/{worker_id}/deactivate',headers=admin_header).status_code==200
    assert client.get('/shield/auth/me',headers=worker_header).status_code==401
    assert login(client,'worker@example.com','worker-password-123').status_code==401


def test_local_mode_has_no_fallback_identity(monkeypatch,tmp_path):
    _,_,client=setup_local(monkeypatch,tmp_path)
    assert client.post('/shield/jobs/job-one/challenge',data={'point_id':'p','account_id':'fake'}).status_code==401
    assert client.get('/shield/auth/me',headers={'Authorization':'Bearer forged'}).status_code==401


def test_local_requires_signing_secret(monkeypatch,tmp_path):
    _,_,client=setup_local(monkeypatch,tmp_path)
    monkeypatch.delenv('SHIELD_LOCAL_JWT_SECRET')
    result=login(client,'admin@example.com','admin-password-123')
    assert result.status_code==503
    assert client.get('/shield/v1/health').status_code==503


def test_local_identity_never_falls_back_to_development_job_access(monkeypatch,tmp_path):
    _,_,client=setup_local(monkeypatch,tmp_path)
    token=login(client,'admin@example.com','admin-password-123').json()['access_token']
    monkeypatch.setenv('SHIELD_AUTHZ_MODE','development')
    header={'Authorization':'Bearer '+token}
    assert client.get('/shield/v1/health').status_code==503
    denied=client.post('/shield/jobs/unassigned/challenge',data={'point_id':'any'},headers=header)
    assert denied.status_code==403
    assert denied.json()['detail']=='local_job_authorization_not_configured'


def test_production_health_requires_platform_configuration(monkeypatch,tmp_path):
    _,_,client=setup_local(monkeypatch,tmp_path)
    monkeypatch.setenv('SHIELD_ATTESTATION_MODE','production')
    monkeypatch.setenv('SHIELD_PLAY_INTEGRITY_MODE','production')
    monkeypatch.delenv('SHIELD_APP_ID',raising=False)
    assert client.get('/shield/v1/health').json()['detail']=='apple_app_id_not_configured'
    monkeypatch.setenv('SHIELD_APP_ID','TEAMID.com.tradedeck.shield')
    monkeypatch.delenv('SHIELD_PLAY_PACKAGE_NAME',raising=False)
    assert client.get('/shield/v1/health').json()['detail']=='play_package_not_configured'
    monkeypatch.setenv('SHIELD_PLAY_PACKAGE_NAME','app.tradedeck.shield')
    monkeypatch.delenv('GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON',raising=False)
    monkeypatch.delenv('GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE',raising=False)
    assert client.get('/shield/v1/health').json()['detail']=='play_integrity_credentials_not_configured'
    monkeypatch.setenv('GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON','{}')
    assert client.get('/shield/v1/health').json()['detail']=='play_integrity_credentials_invalid'
    monkeypatch.setenv('GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON',
                       '{"client_email":"test@example.com","private_key":"test","token_uri":"https://example.com"}')
    assert client.get('/shield/v1/health').status_code==200


def _admin_header(client):
    token = login(client, 'admin@example.com', 'admin-password-123').json()['access_token']
    return {'Authorization': 'Bearer ' + token}


def test_lock_admin_turns_admin_access_off_for_good(monkeypatch, tmp_path):
    local, admin, client = setup_local(monkeypatch, tmp_path)
    admin_header = _admin_header(client)
    created = client.post('/shield/admin/accounts', json={'email': 'worker@example.com', 'password': 'worker-password-123'}, headers=admin_header)
    assert created.status_code == 200
    assert not local.is_locked()

    assert local.lock_admin() == 1
    assert local.is_locked()

    # Every admin route is closed, the admin token that was live a moment ago is dead, and the admin cannot sign in again.
    assert client.get('/shield/admin/health', headers=admin_header).status_code == 403
    assert client.post('/shield/admin/accounts', json={'email': 'x@example.com', 'password': 'x-password-12345'}, headers=admin_header).status_code in {401, 403}
    assert client.get('/shield/auth/me', headers=admin_header).status_code == 401
    assert login(client, 'admin@example.com', 'admin-password-123').status_code == 401
    # No admin can be made or revived any way the server offers.
    for call in (lambda: local.create_account('second@example.com', 'second-password-123', 'admin'),
                 lambda: local.reset_password(admin.id, 'brand-new-password-123')):
        try:
            call()
            raise AssertionError('expected admin_locked')
        except ValueError as exc:
            assert str(exc) in {'admin_locked', 'account_not_found'}
    # Capturer accounts keep working.
    worker = login(client, 'worker@example.com', 'worker-password-123')
    assert worker.status_code == 200
    worker_header = {'Authorization': 'Bearer ' + worker.json()['access_token']}
    assert client.get('/shield/jobs', headers=worker_header).status_code == 200
    assert client.get('/shield/admin/health', headers=worker_header).status_code == 403


def test_lock_survives_removing_the_environment_flag(monkeypatch, tmp_path):
    local, admin, client = setup_local(monkeypatch, tmp_path)
    monkeypatch.setenv('SHIELD_ADMIN_LOCKED', 'true')
    assert local.is_locked()
    assert login(client, 'admin@example.com', 'admin-password-123').status_code == 401
    monkeypatch.delenv('SHIELD_ADMIN_LOCKED')
    # Only the env flag was used so far: nothing permanent is written, so removing it reopens access.
    assert login(client, 'admin@example.com', 'admin-password-123').status_code == 200
    local.lock_admin()
    monkeypatch.delenv('SHIELD_ADMIN_LOCKED', raising=False)
    assert login(client, 'admin@example.com', 'admin-password-123').status_code == 401


def test_bootstrap_admin_does_nothing_once_locked(monkeypatch, tmp_path):
    from app.local_identity import ensure_bootstrap_admin
    path = f"sqlite:///{tmp_path / 'fresh.db'}"
    monkeypatch.setenv('SHIELD_DATABASE_URL', path)
    monkeypatch.setenv('SHIELD_BOOTSTRAP_ADMIN_EMAIL', 'first@example.com')
    monkeypatch.setenv('SHIELD_BOOTSTRAP_ADMIN_PASSWORD', 'first-password-123')
    LocalIdentity(path).lock_admin()
    assert ensure_bootstrap_admin() is False
    assert LocalIdentity(path).authenticate('first@example.com', 'first-password-123') is None
