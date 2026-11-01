"""The phone's EXPORT file (capture-export.v1, written by the app's hardware-signed export) checks with the independent verifier.

Its shape comes from the app's plugin typings (shield-app/plugins/secure-capture/src/index.d.ts): the schema line, the job's anchor
and clock, and per record the signed record, the sensor snapshot, Apple's assertion fields and the hardware signature, with the photo's
bytes on one record only. Built here by the verifier's own rules, not by the server. A real file from a phone has not been run through
this yet."""
import json

from test_verifier import Phone, sv


def package(phone, photos, with_photo_on):
    items = []
    for i, photo in enumerate(photos):
        item = phone.seal(photo)
        if i != with_photo_on:
            del item["photo_b64"]
        item.update(sensor_snapshot={"platform": "ios", "depth": "not_available"}, signature_kind="secure-enclave-p256",
                    app_attest_key_id="key", app_attest_assertion_b64="YXNzZXJ0aW9u", ticket_origin="local", mime="image/jpeg")
        items.append(item)
    return {"schema": "tradedeck.shield.capture-export.v1", "ticket_id": "job-1", "ticket_origin": "local", "anchor_hash": "a" * 64,
            "ticket_clock": {"wall_time_ms": 1_700_000_000_000, "monotonic_ms": 5_000, "boot_count": 4}, "records": items}


def run(tmp_path, doc):
    f = tmp_path / "export.shield.json"
    f.write_text(json.dumps(doc))
    return sv.main([str(f)])


def test_a_whole_chain_with_one_photo_passes_and_says_which_photos_it_did_not_check(tmp_path, capsys):
    doc = package(Phone(), [b"one", b"two", b"three"], with_photo_on=1)
    assert run(tmp_path, doc) == 0
    out = capsys.readouterr().out
    assert out.count("NOT CHECKED photo is the one that was signed") == 2
    assert out.count("pass        photo is the one that was signed") == 1
    assert "RESULT: PASSED" in out


def test_tampering_with_the_photo_or_a_record_in_the_export_fails(tmp_path):
    doc = package(Phone(), [b"one", b"two"], with_photo_on=1)
    doc["records"][1]["photo_b64"] = "c3dhcHBlZA=="
    assert run(tmp_path, doc) == 2
    doc = package(Phone(), [b"one", b"two"], with_photo_on=1)
    doc["records"][0]["record"]["flags"] = 9
    assert run(tmp_path, doc) == 2


def test_dropping_a_record_from_the_chain_fails(tmp_path, capsys):
    doc = package(Phone(), [b"one", b"two", b"three"], with_photo_on=2)
    del doc["records"][1]
    assert run(tmp_path, doc) == 2
    assert "links to the record before it" in capsys.readouterr().out
