"""The labelling sheet converts to a labelled set the harness accepts, and a typo or a duplicate photo is refused, not guessed."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from app import inspection_eval as ev

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("csv_to_set", ROOT / "eval" / "csv_to_set.py")
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)

HEADER = "photo_file,checkpoint,conditions,material:lumber,material:rebar,missing-step:anchor-bolts,defect:honeycomb"


@pytest.fixture
def photos(tmp_path):
    folder = tmp_path / "photos"
    folder.mkdir()
    for name, body in (("a.jpg", b"photo-a"), ("b.jpg", b"photo-b"), ("same-as-a.jpg", b"photo-a")):
        (folder / name).write_bytes(body)
    return folder


def sheet(*rows):
    return "\n".join((HEADER,) + rows)


def test_a_filled_sheet_becomes_a_set_the_harness_accepts(photos):
    dataset, files, warnings = cs.build(sheet("a.jpg,Pre Pour,concrete;Daylight,x,,x,", "b.jpg,,,,x,,x", ",,,,,,"), photos)
    ev.checked_set(dataset)
    a, b = dataset["cases"]
    assert a["photo_sha256"] == hashlib.sha256(b"photo-a").hexdigest() and b["photo_sha256"] == hashlib.sha256(b"photo-b").hexdigest()
    assert a["conditions"] == ["concrete", "daylight", "checkpoint-pre-pour"] and b["conditions"] == []
    assert a["truth"] == {"material": ["lumber"], "missing-step": ["anchor-bolts"], "defect": []}
    assert b["truth"] == {"material": ["rebar"], "missing-step": [], "defect": ["honeycomb"]}
    assert dataset["vocabulary"] == {"material": ["lumber", "rebar"], "missing-step": ["anchor-bolts"], "defect": ["honeycomb"]}
    assert files == {"p001": "a.jpg", "p002": "b.jpg"}  # blank rows are skipped, not numbered
    assert any("defect:honeycomb is present in 1 of 2" in w for w in warnings)


def test_a_label_nobody_has_says_its_recall_cannot_be_measured(photos):
    _, _, warnings = cs.build(sheet("a.jpg,,,x,,,"), photos)
    assert any("missing-step:anchor-bolts" in w and "none" in w for w in warnings)


@pytest.mark.parametrize("bad, message", [
    ("a.jpg,,,y,,,", "put x or leave blank"),                     # a typo is not 'absent'
    ("a.jpg,,,x,,,\na.jpg,,,,x,,", "listed twice"),
    ("a.jpg,,,x,,,\nsame-as-a.jpg,,,,x,,", "same file as a.jpg"),  # the same photo under another name
    ("missing.jpg,,,x,,,", "is not in"),
    ("../a.jpg,,,x,,,", "inside the photo folder"),
    ("a.jpg,,,x,,,,,extra", "more cells than the header"),
    (",,,,,,", "no photo rows"),
])
def test_bad_rows_are_refused_with_the_row_named(photos, bad, message):
    with pytest.raises(cs.SheetError, match=message):
        cs.build(sheet(*bad.split("\n")), photos)


@pytest.mark.parametrize("header", [
    "file,checkpoint,conditions,material:lumber,missing-step:s,defect:d",           # first column must be photo_file
    "photo_file,checkpoint,conditions,material:Lumber,missing-step:s,defect:d",     # uppercase
    "photo_file,checkpoint,conditions,paint:red,missing-step:s,defect:d",           # unknown category
    "photo_file,checkpoint,conditions,material:lumber,material:lumber,missing-step:s,defect:d",
    "photo_file,checkpoint,conditions,material:lumber,missing-step:s",              # a category with no labels
])
def test_bad_headers_are_refused(photos, header):
    with pytest.raises(cs.SheetError):
        cs.build(header + "\na.jpg,,,x,x", photos)


def test_the_shipped_template_header_is_valid_and_has_no_rows():
    text = (ROOT / "eval" / "labels_template.csv").read_text()
    fields, vocab = cs._header(text.strip().split(","))
    assert fields[:3] == ["photo_file", "checkpoint", "conditions"] and all(vocab[c] for c in ev.CATEGORIES)
    with pytest.raises(cs.SheetError, match="no photo rows"):
        cs.build(text, Path("."))


def test_the_command_line_writes_the_set_and_the_file_map(photos, tmp_path, capsys):
    sheet_path, out = tmp_path / "labels.csv", tmp_path / "set.json"
    sheet_path.write_text("﻿" + sheet("a.jpg,,,x,,,", "b.jpg,,,,x,,"), encoding="utf-8")  # Excel adds a byte-order mark
    assert cs.main([str(sheet_path), "--photos", str(photos), "--out", str(out)]) == 0
    ev.checked_set(json.loads(out.read_text()))
    assert json.loads(Path(str(out) + ".files.json").read_text()) == {"p001": "a.jpg", "p002": "b.jpg"}
    sheet_path.write_text(sheet("a.jpg,,,q,,,"))
    out.unlink()
    assert cs.main([str(sheet_path), "--photos", str(photos), "--out", str(out)]) == 2
    assert not out.exists() and "cannot use this sheet" in capsys.readouterr().err
