import importlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from app.attestation_sheet import AttestationSheet
from app.custody_chain import verify_chain
from app.protocol import sha256_bytes, bind_hash
from app.store import Store
from tests.test_verification import make, run


@pytest.mark.parametrize("mutation", [
    "UPDATE custody_events SET event_hash='changed'",
    "UPDATE custody_events SET event_hash=NULL",
    "UPDATE custody_events SET details_json='invalid-json'",
    "DELETE FROM custody_events",
])
def test_independent_verifier_rejects_custody_damage(tmp_path, mutation):
    st, photo, _ = make(tmp_path)
    with st.db() as c:
        c.execute(mutation)
    assert run(st, photo)["ok"] is False


def test_verifier_rejects_illegal_intermediate_history(tmp_path):
    st, photo, _ = make(tmp_path)
    with st.db() as c:
        c.execute("UPDATE state_events SET to_state='voided' WHERE to_state='verified'")
    assert run(st, photo)["checks"]["state_history"]["ok"] is False


def test_no_empty_chain_or_legacy_hash_fallback():
    assert verify_chain([])["valid"] is False
    assert verify_chain([{"id": 1, "event_type": "sealed", "event_at": "time", "details_json": "{}"}])["valid"] is False


@pytest.mark.parametrize("job", ["../outside", "/absolute", "..", "a/b", "a\\b"])
def test_storage_rejects_unsafe_identifiers(tmp_path, job):
    st = Store(f"sqlite:///{tmp_path/'db'}", str(tmp_path/'storage'))
    with pytest.raises(ValueError, match="invalid_storage_identifier"):
        st.save_original("ev", job, "acct", b"original")
    assert not list(tmp_path.rglob("*.jpg"))


def test_storage_rejects_symlink_escape_and_never_overwrites(tmp_path):
    st = Store(f"sqlite:///{tmp_path/'db'}", str(tmp_path/'storage'))
    outside = tmp_path/'outside'
    outside.mkdir()
    (st.root/'job').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe_original_path"):
        st.save_original('ev', 'job', 'acct', b'original')
    (st.root/'job').unlink()
    rel = st.save_original('ev', 'job', 'acct', b'original')
    with pytest.raises(ValueError, match="original_already_exists"):
        st.save_original('ev', 'job', 'acct', b'changed')
    assert st.read_original(rel) == b'original'
    assert st.read_original('../outside/private.jpg') is None


def record(nonce, eid='ev'):
    sheet = AttestationSheet.from_user_input('123 Main St', 'Framing inspection')
    ph, nh = sha256_bytes(b'original'), sheet.sha256
    return dict(id=eid, job_id='job', point_id='point', account_id='acct', nonce=nonce,
                photo_sha256=ph, note_sha256=nh, bind_hash=bind_hash(ph, nh, 'job', 'point', nonce, 'acct'),
                captured_at='2026-09-30T12:00:00Z', written_at='2026-09-30T12:00:01Z',
                location_json='{}', attestation_json='{}', attestation_sheet_json=sheet.canonical_bytes.decode(),
                status='sealed', state='sealed', actor_id='acct')


@pytest.mark.parametrize('replacement', ['{"location_stated":"elsewhere","purpose":"Changed"}', None])
def test_sealing_retains_statement_and_detects_its_tampering(tmp_path, replacement):
    st = Store(f"sqlite:///{tmp_path/'db'}", str(tmp_path/'storage'))
    nonce, _ = st.challenge('job', 'point', 'acct', 120)
    st.accept_capture(b'original', **record(nonce))
    assert json.loads(st.get('ev')['attestation_sheet_json'])['purpose'] == 'Framing inspection'
    assert run(st, b'original')['ok'] is True
    with st.db() as c:
        c.execute("UPDATE evidence SET attestation_sheet_json=?", (replacement,))
    assert run(st, b'original')['ok'] is False


def test_failed_record_write_rolls_back_nonce_counter_and_original(tmp_path, monkeypatch):
    st = Store(f"sqlite:///{tmp_path/'db'}", str(tmp_path/'storage'))
    nonce, _ = st.challenge('job', 'point', 'acct', 120)
    st.save_attestation_key('key', 'acct', 'test-key', 'production', '')
    original_create = st.create_evidence
    def fail(**kw):
        original_create(**kw)
        raise RuntimeError('simulated_write_failure')
    monkeypatch.setattr(st, 'create_evidence', fail)
    with pytest.raises(RuntimeError, match='simulated_write_failure'):
        st.accept_capture(b'original', attestation_key_id='key', attestation_counter=1, **record(nonce))
    assert st.get('ev') is None
    assert st.get_attestation_key('key')['counter'] == 0
    assert not list(st.root.rglob('*.jpg'))
    monkeypatch.setattr(st, 'create_evidence', original_create)
    st.accept_capture(b'original', attestation_key_id='key', attestation_counter=1, **record(nonce))
    assert st.get('ev') is not None


def test_invalid_amendment_creates_nothing_and_leaves_nonce_usable(tmp_path):
    st = Store(f"sqlite:///{tmp_path/'db'}", str(tmp_path/'storage'))
    nonce, _ = st.challenge('job', 'point', 'acct', 120)
    with pytest.raises(ValueError, match='amendment_parent_not_found'):
        st.accept_capture(b'original', amendment_of='missing', **record(nonce))
    assert st.get('ev') is None
    assert not list(st.root.rglob('*.jpg'))
    st.accept_capture(b'original', **record(nonce))


def test_concurrent_same_nonce_accepts_only_one_capture(tmp_path):
    st = Store(f"sqlite:///{tmp_path/'db'}", str(tmp_path/'storage'))
    nonce, _ = st.challenge('job', 'point', 'acct', 120)
    def attempt(eid):
        try:
            st.accept_capture(b'original', **record(nonce, eid))
            return 'accepted'
        except ValueError as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ['one', 'two']))
    assert sorted(results) == ['accepted', 'nonce_replayed']
    assert len(list(st.root.rglob('*.jpg'))) == 1


def test_amendment_and_void_preserve_original_and_verify(tmp_path):
    st = Store(f"sqlite:///{tmp_path/'db'}", str(tmp_path/'storage'))
    nonce, _ = st.challenge('job', 'point', 'acct', 120)
    st.accept_capture(b'original', **record(nonce))
    nonce, _ = st.challenge('job', 'point', 'acct', 120)
    st.accept_capture(b'original', amendment_of='ev', **record(nonce, 'child'))
    assert st.get('ev')['state'] == 'amended'
    assert run(st, b'original')['ok'] is True
    st.void('ev', 'acct', 'Superseded')
    assert st.get('ev')['state'] == 'voided'
    assert run(st, b'original')['ok'] is True


def test_ios_readiness_without_google_and_android_upload_disabled(monkeypatch):
    monkeypatch.setenv('SHIELD_ENABLED_PLATFORMS', 'ios')
    monkeypatch.setenv('SHIELD_ATTESTATION_MODE', 'production')
    monkeypatch.setenv('SHIELD_PLAY_INTEGRITY_MODE', 'production')
    monkeypatch.setenv('SHIELD_APP_ID', 'TEAM.com.tradedeck.shield')
    monkeypatch.delenv('GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON', raising=False)
    monkeypatch.delenv('GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE', raising=False)
    c = TestClient(importlib.import_module('app.main').app)
    assert c.get('/shield/v1/health').status_code == 200
    response = c.post('/shield/jobs/job/photos', data={
        'point_id':'point', 'account_id':'acct', 'nonce':'nonce', 'captured_at':'now',
        'location_stated':'Site', 'purpose':'Inspection', 'play_integrity_token':'untrusted-token',
    }, files={'photo':('photo.jpg', b'original', 'image/jpeg')})
    assert response.status_code == 422
    assert response.json()['detail'] == 'android_capture_disabled'


def test_capture_receipt_and_testimony_are_owner_only():
    main = importlib.import_module('app.main')
    nonce, _ = main.store.challenge('job', 'point', 'acct', 120)
    main.store.accept_capture(b'original', **record(nonce))
    c = TestClient(main.app)
    url = f'/shield/jobs/job/captures/by-nonce/{nonce}'
    assert c.get(url, headers={'x-shield-account-id':'other'}).status_code == 404
    assert c.get(url, headers={'x-shield-account-id':'acct'}).json()['evidence_id'] == 'ev'
    testimony = '/shield/evidence/ev/attestation-sheet'
    assert c.get(testimony, headers={'x-shield-account-id':'other'}).status_code == 403
    assert c.get(testimony, headers={'x-shield-account-id':'acct'}).json()['attestation_sheet']['purpose'] == 'Framing inspection'


def test_location_rejection_does_not_consume_nonce():
    main = importlib.import_module('app.main')
    nonce, _ = main.store.challenge('job', 'point', 'acct', 120)
    c = TestClient(main.app)
    response = c.post('/shield/jobs/job/photos', data={
        'point_id':'point', 'account_id':'acct', 'nonce':nonce, 'captured_at':'now',
        'location_stated':'Site', 'purpose':'Inspection', 'lat':'91', 'lng':'0',
    }, files={'photo':('photo.jpg', b'original', 'image/jpeg')})
    assert response.status_code == 422
    assert response.json()['detail']['code'] == 'location_rejected'
    main.store.consume(nonce, 'job', 'point', 'acct')


def test_mock_location_without_coordinates_still_rejects():
    from app.location import evaluate_location
    assert evaluate_location(mock_flag=True)['verdict'] == 'reject'


def test_backup_restore_retains_testimony_and_complete_custody(tmp_path):
    from app.backup import backup, restore
    db, storage = tmp_path/'db', tmp_path/'storage'
    st = Store(f'sqlite:///{db}', str(storage))
    nonce, _ = st.challenge('job', 'point', 'acct', 120)
    st.accept_capture(b'original', **record(nonce))
    archive = tmp_path/'backup.zip'
    backup(db, storage, archive)
    restore(archive, tmp_path/'restored-db', tmp_path/'restored-storage')
    restored = Store(f"sqlite:///{tmp_path/'restored-db'}", str(tmp_path/'restored-storage'))
    assert json.loads(restored.get('ev')['attestation_sheet_json'])['purpose'] == 'Framing inspection'
    assert run(restored, b'original')['ok'] is True
