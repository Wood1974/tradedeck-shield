import hashlib
import pytest

from app.protocol import (
    CHALLENGE_TTL_SECONDS,
    LocationVerdict,
    PROTOCOL_VERSION,
    bind_hash,
    canonical_note,
    capture_bind,
    note_sha256,
    sha256_bytes,
)


def test_protocol_metadata_is_locked():
    assert PROTOCOL_VERSION == "shield-evidence-v1"
    assert CHALLENGE_TTL_SECONDS == 120
    assert [v.value for v in LocationVerdict] == ["consistent", "flag", "reject"]


def test_hash_is_stable():
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_note_is_canonical_and_required():
    expected = b'{"location_stated":"123 Main St","purpose":"Document completed work"}'
    assert canonical_note(" 123 Main St ", " Document completed work ") == expected
    assert note_sha256("123 Main St", "Document completed work") == hashlib.sha256(expected).hexdigest()

    with pytest.raises(ValueError, match="no_location_stated"):
        canonical_note("   ", "why")
    with pytest.raises(ValueError, match="no_purpose"):
        canonical_note("where", "   ")


def test_bind_uses_locked_direct_concatenation_vector():
    photo = "a" * 64
    note = "b" * 64
    actual_payload = (photo + note + "job-1" + "point-1" + "nonce-1" + "acct-1").encode()
    assert bind_hash(photo, note, "job-1", "point-1", "nonce-1", "acct-1") == hashlib.sha256(actual_payload).hexdigest()
    assert bind_hash(photo, note, "job-1", "point-1", "nonce-1", "acct-1") == "66adc308eca68e2b73d2ccd353237d5ce8bebfa5b92aabfc88d5879eafb6592a"


def test_bind_changes_when_any_identity_or_note_changes():
    base = ("p", "n", "j", "pt", "nonce", "acct")
    for i in range(6):
        altered = list(base)
        altered[i] += "-changed"
        assert bind_hash(*base) != bind_hash(*altered)


def test_capture_bind_is_deterministic():
    result = capture_bind(b"photo-bytes", "123 Main St", "Document completed work", "job", "point", "nonce", "acct")
    assert result["photo_sha256"] == sha256_bytes(b"photo-bytes")
    assert result["note_sha256"] == note_sha256("123 Main St", "Document completed work")
    assert result["bind_hash"] == bind_hash(result["photo_sha256"], result["note_sha256"], "job", "point", "nonce", "acct")
