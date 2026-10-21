"""The independent verifier (verifier/shield_verify.py) and the server must agree, and every kind of tampering must fail."""
import base64
import hashlib
import importlib.util
import json
import random
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import captures

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("shield_verify", ROOT / "verifier" / "shield_verify.py")
sv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "capture-record-v1.json").read_text())
b64 = lambda raw: base64.b64encode(raw).decode("ascii")


class Phone:
    """Seals records using only the verifier's own rules, so the server is not what produced them."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public_b64 = b64(self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        self.prev = "a" * 64

    def seal(self, photo: bytes, **overrides):
        record = {"version": 1, "checkpoint_id": "cp-1", "photo_sha256": hashlib.sha256(photo).hexdigest(), "ticket_id": "job-1",
                  "wall_time_ms": 1_700_000_000_000, "monotonic_ms": 5_000, "boot_count": 4, "flags": 0, **overrides}
        record["prev_hash"] = self.prev
        message = sv.signing_message(record)
        record["record_hash"] = hashlib.sha256(message).hexdigest()
        signature = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        self.prev = record["record_hash"]
        return {"record": record, "signature_der_b64": b64(signature), "public_key_uncompressed_b64": self.public_b64, "photo_b64": b64(photo)}


def states(item, photo=None):
    return {name: state for name, state, _ in sv.check_item(item, photo)}


def test_frozen_vector_hashes_the_same_way():
    record = json.loads(VECTORS["canonicalRequired"])
    assert sv.canonical(record).decode() == VECTORS["canonicalRequired"]
    record["prev_hash"] = VECTORS["prevHash"]
    assert hashlib.sha256(sv.signing_message(record)).hexdigest() == VECTORS["recordHashRequired"]
    full = json.loads(VECTORS["canonicalFull"])
    assert sv.canonical(full).decode() == VECTORS["canonicalFull"]


def test_a_good_record_passes_every_check():
    item = Phone().seal(b"original photo bytes")
    assert set(states(item).values()) == {"pass"}


def test_agrees_with_the_server_on_many_random_records():
    rng = random.Random(7)
    for _ in range(200):
        record = {"version": 1, "checkpoint_id": f"cp-{rng.randrange(99)}", "photo_sha256": hashlib.sha256(bytes([rng.randrange(256)])).hexdigest(),
                  "ticket_id": "t" * rng.randrange(1, 40), "wall_time_ms": rng.randrange(0, 2 ** 53), "monotonic_ms": rng.randrange(0, 2 ** 40),
                  "flags": rng.randrange(0, 255)}
        if rng.random() < 0.5:
            record["boot_count"] = rng.randrange(0, 1000)
        if rng.random() < 0.5:
            record["boot_id"] = "café-" + str(rng.randrange(1000))
        if rng.random() < 0.5:
            record["gnss_time_ms"] = rng.randrange(0, 2 ** 53)
        if rng.random() < 0.5:
            record["location_simulated"] = rng.random() < 0.5
        prev = "".join(rng.choice("0123456789abcdef") for _ in range(64))
        assert sv.canonical(record) == captures.canonical_bytes(record)
        assert hashlib.sha256(sv.signing_message({**record, "prev_hash": prev})).hexdigest() == captures.record_hash_of(record, prev)


@pytest.mark.parametrize("field,value", [("wall_time_ms", 1_700_000_000_001), ("checkpoint_id", "cp-2"), ("flags", 1), ("ticket_id", "other")])
def test_editing_any_signed_field_is_caught(field, value):
    item = Phone().seal(b"photo")
    item["record"][field] = value
    assert states(item)["record hash matches the signed fields"] == "FAIL"


def test_a_different_or_recompressed_photo_is_caught():
    item = Phone().seal(b"original")
    assert states(item, photo=b"original")["photo is the one that was signed"] == "pass"
    assert states(item, photo=b"original recompressed")["photo is the one that was signed"] == "FAIL"
    item["photo_b64"] = b64(b"swapped")
    assert states(item)["photo is the one that was signed"] == "FAIL"


def test_no_photo_is_not_reported_as_a_pass():
    item = Phone().seal(b"photo")
    del item["photo_b64"]
    assert states(item)["photo is the one that was signed"] == "NOT CHECKED"


def test_a_signature_from_another_key_or_over_other_bytes_is_caught():
    phone, other = Phone(), Phone()
    item = phone.seal(b"photo")
    item["public_key_uncompressed_b64"] = other.public_b64
    assert states(item)["device signature"] == "FAIL"
    a, b = phone.seal(b"one"), phone.seal(b"two")
    a["signature_der_b64"] = b["signature_der_b64"]
    assert states(a)["device signature"] == "FAIL"


def test_a_field_the_signature_does_not_cover_is_refused():
    item = Phone().seal(b"photo")
    item["record"]["note"] = "added later"
    assert states(item) == {"fields and canonical form": "FAIL"}


@pytest.mark.parametrize("bad", [{"wall_time_ms": 1.5}, {"wall_time_ms": True}, {"flags": -1}, {"photo_sha256": "A" * 64}, {"depth_present": True}, {"version": 2}])
def test_malformed_values_are_refused(bad):
    item = Phone().seal(b"photo")
    item["record"].update(bad)
    assert states(item)["fields and canonical form"] == "FAIL"


def test_without_the_cryptography_package_the_signature_is_not_checked(monkeypatch):
    import builtins
    item = Phone().seal(b"photo")  # sealed first: signing itself needs the package
    real = builtins.__import__

    def no_crypto(name, *a, **k):
        if name.startswith("cryptography"):
            raise ImportError(name)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_crypto)
    assert states(item)["device signature"] == "NOT CHECKED"


def run(tmp_path, doc, *extra):
    f = tmp_path / "in.json"
    f.write_text(json.dumps(doc))
    return sv.main([str(f), *extra])


def test_exit_codes_and_chain_links(tmp_path, capsys):
    phone = Phone()
    a, b, c = phone.seal(b"1"), phone.seal(b"2"), phone.seal(b"3")
    assert run(tmp_path, [a, b, c]) == 0
    assert "RESULT: PASSED" in capsys.readouterr().out
    assert run(tmp_path, {"records": [a, c]}) == 2          # b is missing: c does not link to a
    assert "links to the record before it" in capsys.readouterr().out
    assert run(tmp_path, {"packages": [{"records": [a, b]}]}) == 0
    b["record"]["flags"] = 9
    assert run(tmp_path, [a, b]) == 2


def test_photo_options(tmp_path):
    phone = Phone()
    a = phone.seal(b"original")
    del a["photo_b64"]
    photo = tmp_path / "p.jpg"
    photo.write_bytes(b"original")
    assert run(tmp_path, a, "--photo", str(photo)) == 0
    photo.write_bytes(b"changed")
    assert run(tmp_path, a, "--photo", str(photo)) == 2
    folder = tmp_path / "originals"
    folder.mkdir()
    (folder / f"{a['record']['record_hash']}.jpg").write_bytes(b"original")
    assert run(tmp_path, a, "--photos", str(folder)) == 0


def test_unreadable_input_fails_cleanly(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not json")
    assert sv.main([str(f)]) == 2
    assert sv.main([str(tmp_path / "missing.json")]) == 2
