import pytest
from app.attestation_sheet import AttestationSheet
from app.protocol import canonical_note, sha256_bytes


def test_sheet_uses_protocol_canonical_bytes():
    s=AttestationSheet.from_user_input("  123 Main St  ", "  Document framing before cover  ")
    assert s.canonical_bytes == canonical_note("123 Main St", "Document framing before cover")
    assert s.sha256 == sha256_bytes(s.canonical_bytes)

@pytest.mark.parametrize("location,purpose,error", [
    (None,"work","attestation_sheet_required"),
    ("site",None,"attestation_sheet_required"),
    ("   ","work","location_stated_required"),
    ("site","  ","purpose_required"),
])
def test_sheet_rejects_missing_testimony(location,purpose,error):
    with pytest.raises(ValueError, match=error): AttestationSheet.from_user_input(location,purpose)

def test_sheet_does_not_accept_oversize_fields():
    with pytest.raises(ValueError, match="location_stated_too_long"):
        AttestationSheet.from_user_input("x"*501,"work")
    with pytest.raises(ValueError, match="purpose_too_long"):
        AttestationSheet.from_user_input("site","x"*1001)
