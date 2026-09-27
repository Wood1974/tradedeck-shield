from fastapi.testclient import TestClient
from app.main import app
import importlib

def test_challenge_capture_verify():
    c=TestClient(app)
    r=c.post('/shield/jobs/job-test/challenge',data={'point_id':'p1','account_id':'a1'})
    assert r.status_code==200
    nonce=r.json()['nonce']
    r=c.post('/shield/jobs/job-test/photos',data={'point_id':'p1','account_id':'a1','nonce':nonce,'location_stated':'10 Main St','purpose':'Framing inspection','captured_at':'2026-09-25T12:00:00Z','lat':'40.0','lng':'-111.0','accuracy_m':'8','mock_flag':'false'},files={'photo':('x.jpg',b'photo-bytes','image/jpeg')})
    assert r.status_code==200
    eid=r.json()['evidence_id']
    verification=c.get('/shield/evidence/'+eid+'/verify',headers={'x-shield-account-id':'a1'})
    assert verification.status_code==200
    assert verification.json()['ok'] is True
    replay=c.post('/shield/jobs/job-test/photos',data={'point_id':'p1','account_id':'a1','nonce':nonce,'location_stated':'10 Main St','purpose':'Framing inspection','captured_at':'2026-09-25T12:00:00Z'},files={'photo':('x.jpg',b'x','image/jpeg')})
    assert replay.status_code==409


def test_production_apple_capture_does_not_require_play_token(monkeypatch):
    main = importlib.import_module('app.main')
    monkeypatch.setenv('SHIELD_ATTESTATION_MODE', 'production')
    monkeypatch.setenv('SHIELD_PLAY_INTEGRITY_MODE', 'production')
    monkeypatch.setattr(main.att, 'verify_assertion', lambda *args, **kwargs: {'trusted': True, 'status': 'verified', 'counter': 1})
    monkeypatch.setattr(main.att, 'update_counter', lambda *args, **kwargs: True)
    c = TestClient(app)
    challenge = c.post('/shield/jobs/apple-job/challenge', data={'point_id': 'apple-point', 'account_id': 'apple-account'})
    assert challenge.status_code == 200
    result = c.post('/shield/jobs/apple-job/photos', data={
        'point_id': 'apple-point', 'account_id': 'apple-account', 'nonce': challenge.json()['nonce'],
        'location_stated': 'Job site', 'purpose': 'Document framing',
        'captured_at': '2026-09-25T12:00:00Z', 'attestation_key_id': 'apple-key',
        'attestation_assertion': 'signed-assertion',
    }, files={'photo': ('apple.jpg', b'photo-bytes', 'image/jpeg')})
    assert result.status_code == 200, result.text
    assert result.json()['attestation']['apple']['trusted'] is True


def test_production_capture_requires_verified_platform(monkeypatch):
    monkeypatch.setenv('SHIELD_ATTESTATION_MODE', 'production')
    monkeypatch.setenv('SHIELD_PLAY_INTEGRITY_MODE', 'production')
    c = TestClient(app)
    challenge = c.post('/shield/jobs/untrusted-job/challenge', data={'point_id': 'p1', 'account_id': 'a1'})
    assert challenge.status_code == 200
    result = c.post('/shield/jobs/untrusted-job/photos', data={
        'point_id': 'p1', 'account_id': 'a1', 'nonce': challenge.json()['nonce'],
        'location_stated': 'Job site', 'purpose': 'Document framing',
        'captured_at': '2026-09-25T12:00:00Z',
    }, files={'photo': ('untrusted.jpg', b'photo-bytes', 'image/jpeg')})
    assert result.status_code == 422
    assert result.json()['detail'] == 'platform_attestation_required'
