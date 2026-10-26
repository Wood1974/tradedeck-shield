"""verifier/shield_vault_verify.py must accept what the app really exports (frozen vectors made by the app's own sealing code)
and fail on every kind of tampering. The same vectors are checked by the app's own tests in Tradeneck."""
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("shield_vault_verify", ROOT / "verifier" / "shield_vault_verify.py")
vv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vv)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "vault-v1.json").read_text())
NOW = 1_900_000_000  # far later than the vector times


def states(rows):
    return {name: state for name, state, _ in rows}


def failures(rows):
    return [name for name, state, _ in rows if state == "FAIL"]


def run(doc, tmp_path, *extra):
    path = tmp_path / "doc.json"
    path.write_text(json.dumps(doc))
    return vv.main([str(path), *extra])


@pytest.mark.parametrize("value,text", [
    (5.0, "5"), (4.5, "4.5"), (0.5, "0.5"), (-0.0, "0"), (1e-7, "1e-7"), (1.5e-7, "1.5e-7"), (0.000001, "0.000001"),
    (1e21, "1e+21"), (1e20, "100000000000000000000"), (123456789.125, "123456789.125"), (-40.760779, "-40.760779"),
    (40, "40"), (2 ** 53, "9007199254740992"),
])
def test_numbers_are_written_the_way_javascript_writes_them(value, text):
    assert vv.js_number(value) == text


def test_canonical_sorts_keys_and_leaves_non_ascii_alone():
    assert vv.canonical({"b": [1, 2.5, None, True], "a": "ü🚧"}) == '{"a":"ü🚧","b":[1,2.5,null,true]}'


def test_real_bundle_passes():
    rows = vv.bundle_rows(VECTORS["bundle"])
    assert failures(rows) == []
    assert states(rows)["record signature"] == "pass"
    assert states(rows)["photo bytes match the signed hash"] == "pass"


def test_real_packet_passes():
    rows = vv.packet_rows(VECTORS["packet"], None, NOW)
    assert failures(rows) == []
    s = states(rows)
    assert s["packet hash recomputes"] == "pass" and s["packet signature"] == "pass"
    assert s["counts add up"] == "pass"
    assert "photographer note and ID receipt" not in s  # this vector was made without a note


def test_a_packet_with_a_note_reports_the_note_as_not_checked():
    doc = packet()
    doc["photographer"] = {"attestationId": "a", "noteSha256": "b", "note": {}, "receipt": None, "idCheck": {}}
    rows = vv.packet_rows(doc, None, NOW)
    assert states(rows)["photographer note and ID receipt"] == "NOT CHECKED"
    assert "packet hash recomputes" in failures(rows)  # adding a note after signing is itself a change


def test_command_line_exit_codes(tmp_path):
    assert run(VECTORS["bundle"], tmp_path) == 0
    bad = copy.deepcopy(VECTORS["bundle"])
    bad["record"]["sha256"] = "0" * 64
    assert run(bad, tmp_path) == 2
    assert run({"hello": 1}, tmp_path) == 2
    (tmp_path / "x.json").write_text("not json")
    assert vv.main([str(tmp_path / "x.json")]) == 2
    assert vv.main([str(tmp_path / "missing.json")]) == 2


def test_exit_3_when_signatures_cannot_be_checked(tmp_path, monkeypatch):
    monkeypatch.setattr(vv, "signature_state", lambda *a, **k: "unavailable")
    assert run(VECTORS["bundle"], tmp_path) == 3
    bad = copy.deepcopy(VECTORS["bundle"])
    bad["record"]["sha256"] = "0" * 64
    assert run(bad, tmp_path) == 2  # a failure is never hidden by the missing package


def test_runs_as_a_script_without_importing_shield_code(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps(VECTORS["bundle"]))
    done = subprocess.run([sys.executable, "-I", str(ROOT / "verifier" / "shield_vault_verify.py"), str(path)], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "RESULT: PASSED" in done.stdout


# --- every kind of change to a bundle fails ---

def bundle():
    return copy.deepcopy(VECTORS["bundle"])


def test_bundle_edited_field_fails():
    doc = bundle()
    doc["record"]["gps"]["lat"] = 41.0
    assert "record signature" in failures(vv.bundle_rows(doc)) or "chain head recomputes" in failures(vv.bundle_rows(doc))


def test_bundle_edited_field_with_recomputed_chain_still_fails_signature():
    doc = bundle()
    doc["record"]["gps"]["lat"] = 41.0
    r = doc["record"]
    unsigned = {k: v for k, v in r.items() if k not in ("chainHead", "signature")}
    r["chainHead"] = vv.sha256_hex((str(r["prevChain"]) + "|" + vv.sha256_hex(vv.canonical(unsigned).encode())).encode())
    f = failures(vv.bundle_rows(doc))
    assert "record signature" in f and "chain head recomputes" not in f


def test_bundle_swapped_photo_fails():
    doc = bundle()
    raw = bytearray(__import__("base64").b64decode(doc["originalB64"]))
    raw[-1] ^= 1
    doc["originalB64"] = __import__("base64").b64encode(bytes(raw)).decode()
    assert "photo bytes match the signed hash" in failures(vv.bundle_rows(doc))


def test_bundle_bad_base64_fails():
    doc = bundle()
    doc["originalB64"] = "!!!"
    assert "photo bytes readable" in failures(vv.bundle_rows(doc))


def test_bundle_other_key_fails():
    doc = bundle()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    point = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    doc["devicePublicKey"] = __import__("base64").b64encode(point).decode()
    f = failures(vv.bundle_rows(doc))
    assert "seal ID belongs to the key" in f and "record signature" in f


def test_bundle_bad_chain_head_fails():
    doc = bundle()
    doc["record"]["chainHead"] = "0" * 64
    assert "chain head recomputes" in failures(vv.bundle_rows(doc))


def test_bundle_truncated_signature_fails():
    doc = bundle()
    doc["record"]["signature"] = doc["record"]["signature"][:-8]
    assert "record signature" in failures(vv.bundle_rows(doc))


def test_bundle_not_native_camera_fails():
    doc = bundle()
    doc["record"]["captureKind"] = "gallery"
    assert "capture kind is native-camera" in failures(vv.bundle_rows(doc))


def test_bundle_without_key_fails():
    doc = bundle()
    del doc["devicePublicKey"]
    assert "signing key present" in failures(vv.bundle_rows(doc))


# --- every kind of change to a packet fails ---

def packet():
    return copy.deepcopy(VECTORS["packet"])


def test_packet_edited_field_fails_hash_and_signature():
    doc = packet()
    doc["job"]["title"] = "changed" if "title" in doc["job"] else doc["job"].setdefault("title", "x")
    f = failures(vv.packet_rows(doc, None, NOW))
    assert "packet hash recomputes" in f and "packet signature" in f


def test_packet_counts_must_match():
    doc = packet()
    doc["counts"]["sealed"] += 1
    f = failures(vv.packet_rows(doc, None, NOW))
    assert "counts add up" in f and "packet hash recomputes" in f


def test_packet_altered_hash_fails():
    doc = packet()
    doc["integrity"]["hash"] = "0" * 64
    assert "packet hash recomputes" in failures(vv.packet_rows(doc, None, NOW))


def test_packet_signer_pin():
    doc = packet()
    seal = doc["deviceSealId"]
    assert states(vv.packet_rows(doc, seal.lower(), NOW))["signer"] == "pass"
    assert states(vv.packet_rows(doc, "00000000·00000000", NOW))["signer"] == "FAIL"
    assert states(vv.packet_rows(doc, None, NOW))["signer"] == "info"


def test_packet_future_time_is_flagged():
    assert "no time in the future" in failures(vv.packet_rows(packet(), None, 1_000_000))


def test_packet_inner_record_edit_fails():
    doc = packet()
    point = next(p for p in doc["points"] if p.get("record"))
    point["record"]["gps"]["lat"] = 1.25
    f = failures(vv.packet_rows(doc, None, NOW))
    assert any("record signature" in n for n in f)


def test_packet_duplicate_record_fails():
    doc = packet()
    sealed = [p for p in doc["points"] if p.get("record")]
    sealed[1]["record"] = copy.deepcopy(sealed[0]["record"])
    f = failures(vv.packet_rows(doc, None, NOW))
    assert "no duplicate records" in f and "no forked chain" in f


def test_packet_note_missing_when_photos_claim_one():
    doc = packet()
    doc.pop("photographer", None)
    # the vector's photos do not belong to a note, so this only asserts the rule fires when they do
    point = next(p for p in doc["points"] if p.get("record"))
    point["record"]["attestationId"] = "x"
    assert "photographer note present" in failures(vv.packet_rows(doc, None, NOW))


def test_packet_dropped_integrity_is_unreadable():
    doc = packet()
    del doc["points"]
    with pytest.raises(vv.Unreadable):
        vv.packet_rows(doc, None, NOW)
