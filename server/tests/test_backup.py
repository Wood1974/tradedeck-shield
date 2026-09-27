import hashlib
import zipfile

import pytest

from app.backup import backup, restore, verify
from app.local_identity import LocalIdentity
from app.store import Store


def sample(tmp_path):
    db = tmp_path / 'source' / 'shield.db'
    db.parent.mkdir()
    storage = tmp_path / 'source' / 'storage'
    store = Store(f'sqlite:///{db}', str(storage))
    identity = LocalIdentity(f'sqlite:///{db}')
    account = identity.create_account('worker@example.com','long-test-password-123')
    photo = b'original JPEG test bytes'
    relative = store.save_original('photo-1','job-1',account.id,photo)
    with store.db() as connection:
        connection.execute('''INSERT INTO evidence
           (id,job_id,point_id,account_id,nonce,photo_sha256,note_sha256,bind_hash,
            captured_at,written_at,location_json,attestation_json,original_path,status,state)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
           ('photo-1','job-1','point-1',account.id,'nonce-1',hashlib.sha256(photo).hexdigest(),
            'note-hash','bind-hash','2026-09-27T00:00:00Z','2026-09-27T00:00:01Z','{}','{}',relative,'sealed','sealed'))
    return db, storage, photo, relative, account


def test_backup_round_trip_restores_accounts_evidence_and_originals(tmp_path):
    db, storage, photo, relative, account = sample(tmp_path)
    archive = tmp_path / 'archive.zip'
    backup(db,storage,archive)
    verify(archive)
    restored_db = tmp_path / 'restored' / 'shield.db'
    restored_storage = tmp_path / 'restored' / 'storage'
    restore(archive,restored_db,restored_storage)
    assert (restored_storage / relative).read_bytes() == photo
    assert LocalIdentity(f'sqlite:///{restored_db}').authenticate('worker@example.com','long-test-password-123').id == account.id
    assert Store(f'sqlite:///{restored_db}',str(restored_storage)).get('photo-1')['original_path'] == relative
    with pytest.raises(FileExistsError):
        restore(archive,restored_db,restored_storage)


def test_backup_refuses_damaged_original(tmp_path):
    db, storage, _, relative, _ = sample(tmp_path)
    (storage / relative).write_bytes(b'changed')
    archive = tmp_path / 'archive.zip'
    with pytest.raises(ValueError,match='original_hash_mismatch'):
        backup(db,storage,archive)
    assert not archive.exists()


def test_restore_refuses_corrupt_archive_without_writing(tmp_path):
    db, storage, _, _, _ = sample(tmp_path)
    archive = tmp_path / 'archive.zip'
    backup(db,storage,archive)
    with zipfile.ZipFile(archive,'a') as bundle:
        bundle.writestr('storage/extra.jpg',b'unlisted')
    target_db = tmp_path / 'restored' / 'shield.db'
    target_storage = tmp_path / 'restored' / 'storage'
    with pytest.raises(ValueError,match='invalid_backup_manifest'):
        restore(archive,target_db,target_storage)
    assert not target_db.exists() and not target_storage.exists()
