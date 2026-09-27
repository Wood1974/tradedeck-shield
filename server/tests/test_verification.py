from pathlib import Path
from app.store import Store
from app.protocol import sha256_bytes, bind_hash
from app.attestation_sheet import AttestationSheet
from app.verification import verify_record

def make(tmp_path):
    st=Store(f"sqlite:///{tmp_path/'v.db'}", str(tmp_path/'objects'))
    photo=b'original jpeg bytes'; sheet=AttestationSheet.from_user_input('123 Main St','Document rough-in')
    ph=sha256_bytes(photo); nh=sheet.sha256; bh=bind_hash(ph,nh,'job','point','nonce','acct')
    rel=st.save_original('ev','job','acct',photo)
    st.create_evidence(id='ev',job_id='job',point_id='point',account_id='acct',nonce='nonce',photo_sha256=ph,note_sha256=nh,bind_hash=bh,captured_at='2026-01-01T00:00:00Z',written_at='2026-01-01T00:00:01Z',location_json='{}',attestation_json='{}',original_path=rel,status='sealed',state='sealed',actor_id='acct',state_history=['capture_received','verified','sealed'])
    return st, photo, sheet

def run(st, photo, **kw):
    r=st.get('ev'); return verify_record(r,(st.root/r['original_path']).read_bytes(),state_history=st.state_history('ev'),custody_events=st.custody_history('ev'),**kw)

def test_server_original_verifies(tmp_path):
    st,photo,sheet=make(tmp_path); assert run(st,photo)['ok'] is True

def test_supplied_original_verifies(tmp_path):
    st,photo,sheet=make(tmp_path); assert run(st,photo,supplied_original=photo)['checks']['supplied_original']['ok'] is True

def test_modified_original_fails(tmp_path):
    st,photo,sheet=make(tmp_path); r=run(st,photo,supplied_original=photo+b'x'); assert r['ok'] is False and 'supplied_original' in r['failed_checks']

def test_attestation_sheet_recomputed(tmp_path):
    st,photo,sheet=make(tmp_path); r=run(st,photo,location_stated=sheet.location_stated,purpose=sheet.purpose); assert r['checks']['attestation_sheet']['ok'] is True and r['ok'] is True

def test_changed_statement_fails(tmp_path):
    st,photo,sheet=make(tmp_path); r=run(st,photo,location_stated='Elsewhere',purpose=sheet.purpose); assert r['ok'] is False

def test_missing_stored_original_fails(tmp_path):
    st,photo,sheet=make(tmp_path); row=st.get('ev'); (st.root/row['original_path']).unlink(); r=verify_record(row,None,state_history=st.state_history('ev'),custody_events=st.custody_history('ev')); assert r['ok'] is False
