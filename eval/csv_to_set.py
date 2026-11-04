#!/usr/bin/env python3
"""Turn the labelling spreadsheet (CSV) into the labelled set the evaluation harness reads. Standard library only. No network.

    python eval/csv_to_set.py labels.csv --photos /path/to/photo/folder --out eval_set.json

Writes `eval_set.json` (an `inspection_eval_set.v1`) and `eval_set.json.files.json` (which case id is which photo file, so a wrong or
missed case in a run can be found again). The photo's SHA-256 is computed from the ORIGINAL file; nothing is uploaded.
Only JPEG files up to 15 MB are accepted, because that is all the Shield server stores: labelling other kinds of file would measure
photos Shield never receives.

The sheet: one row per photo. `photo_file` is the file name inside --photos. `checkpoint` (optional) is where in the job it was
taken, for example `pre-pour`; it is kept as a condition tag `checkpoint-pre-pour`. `conditions` (optional) are tags separated by
semicolons, for example `concrete;daylight`. Every other column is `category:label`, with the category one of `material`,
`missing-step`, `defect`. Put `x` where the label is truly present; leave it blank where it is not. Anything else in a label cell is
refused, so a typo is caught instead of silently meaning "absent".

For `missing-step:` columns, `x` means the step is expected at this checkpoint and is NOT done in the photo.

Exit code: 0 written; 2 the sheet or photos are not usable (nothing written). Warnings (a label with few examples) do not stop it.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
from app import inspection_eval as ev  # noqa: E402  (the harness's own checks decide what a valid set is)

FIXED = ("photo_file", "checkpoint", "conditions")
SLUG = re.compile(r"[^a-z0-9._-]+")
FEW = 10  # warn when a label has fewer present photos than this
JPEG_MAGIC = b"\xff\xd8\xff"
MAX_PHOTO_BYTES = 15 * 1024 * 1024  # the Shield server's default limit (SHIELD_MAX_PHOTO_BYTES); it accepts JPEG only


class SheetError(ValueError):
    pass


def _slug(text: str) -> str:
    return SLUG.sub("-", text.strip().lower()).strip("-")


def _header(fields: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    if not fields or fields[0] != "photo_file":
        raise SheetError("the first column must be photo_file")
    vocab: dict[str, list[str]] = {c: [] for c in ev.CATEGORIES}
    for name in fields:
        if name in FIXED:
            continue
        category, _, label = name.partition(":")
        if category not in vocab or not label or label != _slug(label):
            raise SheetError(f"column {name!r} must look like material:lumber, missing-step:anchor-bolts or defect:crack (lowercase, no spaces)")
        if label in vocab[category]:
            raise SheetError(f"column {name!r} appears twice")
        vocab[category].append(label)
    return fields, vocab


def build(csv_text: str, photos: Path) -> tuple[dict, dict, list[str]]:
    rows = list(csv.reader(csv_text.splitlines()))
    if not rows:
        raise SheetError("the sheet is empty")
    fields, vocab = _header([f.strip() for f in rows[0]])
    cases, files, seen_files, hashes = [], {}, set(), {}
    counts = {f"{c}:{l}": 0 for c in vocab for l in vocab[c]}
    for line_no, raw in enumerate(rows[1:], start=2):
        if not any(cell.strip() for cell in raw):
            continue  # a blank row
        if len(raw) > len(fields):
            raise SheetError(f"row {line_no} has more cells than the header")
        cells = dict(zip(fields, [c.strip() for c in raw] + [""] * (len(fields) - len(raw))))
        name = cells["photo_file"]
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            raise SheetError(f"row {line_no}: photo_file must be a file name inside the photo folder")
        if name in seen_files:
            raise SheetError(f"row {line_no}: {name} is listed twice")
        seen_files.add(name)
        path = photos / name
        if not path.is_file():
            raise SheetError(f"row {line_no}: {name} is not in {photos}")
        data = path.read_bytes()
        if not data.startswith(JPEG_MAGIC):
            raise SheetError(f"row {line_no}: {name} is not a JPEG. Shield stores JPEG only and its camera makes JPEG; a HEIC or PNG photo may "
                             "behave differently, so it would not tell you how Shield's photos do")
        if len(data) > MAX_PHOTO_BYTES:
            raise SheetError(f"row {line_no}: {name} is {len(data) // (1024 * 1024)} MB; the Shield server's limit is 15 MB")
        digest = hashlib.sha256(data).hexdigest()
        if digest in hashes:
            raise SheetError(f"row {line_no}: {name} is the same file as {hashes[digest]} (one photo cannot count twice)")
        hashes[digest] = name
        conditions = [_slug(t) for t in cells["conditions"].split(";") if t.strip()]
        if cells["checkpoint"]:
            conditions.append("checkpoint-" + _slug(cells["checkpoint"]))
        truth = {c: [] for c in vocab}
        for col in fields:
            if col in FIXED:
                continue
            value = cells[col]
            if value == "":
                continue
            if value.lower() != "x":
                raise SheetError(f"row {line_no}, column {col}: put x or leave blank, not {value!r}")
            category, _, label = col.partition(":")
            truth[category].append(label)
            counts[col] += 1
        case_id = f"p{len(cases) + 1:03d}"
        cases.append({"case_id": case_id, "photo_sha256": digest, "conditions": conditions, "truth": truth})
        files[case_id] = name
    if not cases:
        raise SheetError("the sheet has no photo rows")
    dataset = {"dataset_version": ev.EVAL_SET_VERSION, "vocabulary": vocab, "cases": cases}
    try:
        ev.checked_set(dataset)
    except ev.Invalid as exc:
        raise SheetError(str(exc)) from None
    warnings = [f"{key} is present in {n} of {len(cases)} photos" + (" (none: its recall cannot be measured)" if n == 0 else " (few: its interval will be wide)")
                for key, n in counts.items() if n < FEW]
    return dataset, files, warnings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Convert the labelling CSV into an inspection_eval_set.v1.")
    ap.add_argument("csv", help="the filled-in labels spreadsheet, saved as CSV")
    ap.add_argument("--photos", required=True, help="folder holding the original photo files")
    ap.add_argument("--out", required=True, help="where to write the labelled set JSON")
    args = ap.parse_args(argv)
    try:
        dataset, files, warnings = build(Path(args.csv).read_text(encoding="utf-8-sig"), Path(args.photos))
    except (SheetError, OSError, UnicodeDecodeError) as exc:
        print(f"cannot use this sheet: {exc}", file=sys.stderr)
        return 2
    Path(args.out).write_text(json.dumps(dataset, indent=2, sort_keys=True), encoding="utf-8")
    Path(args.out + ".files.json").write_text(json.dumps(files, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {len(dataset['cases'])} photos to {args.out}")
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
