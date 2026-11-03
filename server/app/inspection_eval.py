"""Measure how often an AI's inspection findings are right, on photos a person has labelled. No model is called here.

Input 1, the labelled set (`inspection_eval_set.v1`): a vocabulary of labels per category (material, missing-step, defect) and cases.
Each case is one photo (by hash) with the labels that are truly present in it, per category, and optional `conditions` tags
(for example "concrete", "daylight") so a result can say what it was tested on.
Input 2, a submission: the model id, the prompt hash and, for every case, the findings the model produced as (case, category,
label, status, confidence). `status` is `found` or `abstain`.

For every (case, label) pair the truth is present or absent, and the model either asserted the label (`found`), abstained, or said
nothing. From that, per category: true and false positives, missed labels, abstentions, precision, recall and the abstain rate, each
rate with a 95% Wilson interval, plus the list of every wrong or missed pair. Rates are whole permille (0 to 1000), with the
interval rounded outward, so nothing here depends on floating-point text.

Fails closed. A category is "validated" only if thresholds the OWNER supplied are met by the interval's lower bound (not the point
estimate) on at least the owner's minimum number of present labels. With no thresholds, or too few cases, it is "not-validated" and the
reasons are listed. Every case must have at least one finding or abstention, so a model cannot look better by skipping hard photos.

What a result is: the numbers for this model, this prompt and this set of photos. It says nothing about other photos, other
lighting, other trades or a changed model. The report names the conditions it was tested on and the number of photos.
The run is content-addressed (`run_id` hashes the set, the model, the prompt, the predictions and the thresholds). It is not signed yet.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import time

CATEGORIES = ("material", "missing-step", "defect")
STATUSES = ("found", "abstain")
EVAL_SET_VERSION = 1
RUN_VERSION = 1
Z95 = 1.959963984540054
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class Invalid(ValueError):
    """The labelled set, the submission or the thresholds are not usable. The message says why."""


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_of(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def wilson_permille(k: int, n: int) -> tuple[int, int, int] | None:
    """(point, lower, upper) as whole permille for k successes in n, 95% Wilson interval rounded outward. None when n is 0."""
    if n <= 0:
        return None
    p = k / n
    z2 = Z95 * Z95
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = Z95 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    lower = max(0, math.floor((centre - half) * 1000))
    upper = min(1000, math.ceil((centre + half) * 1000))
    return round(p * 1000), lower, upper


def _labels(value, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) and _ID.fullmatch(x) for x in value) or len(set(value)) != len(value):
        raise Invalid(f"{what} must be a list of distinct short labels")
    return value


def checked_set(dataset) -> dict:
    if not isinstance(dataset, dict) or dataset.get("dataset_version") != EVAL_SET_VERSION or type(dataset.get("dataset_version")) is not int:
        raise Invalid("not an inspection_eval_set.v1")
    vocab = dataset.get("vocabulary")
    if not isinstance(vocab, dict) or set(vocab) != set(CATEGORIES):
        raise Invalid("vocabulary needs exactly material, missing-step and defect")
    for cat in CATEGORIES:
        if not _labels(vocab[cat], f"vocabulary.{cat}"):
            raise Invalid(f"vocabulary.{cat} is empty")
    cases = dataset.get("cases")
    if not isinstance(cases, list) or not cases:
        raise Invalid("the set has no cases")
    ids, photos = set(), set()
    for case in cases:
        if not isinstance(case, dict) or set(case) - {"case_id", "photo_sha256", "conditions", "truth"} or not {"case_id", "photo_sha256", "truth"} <= set(case):
            raise Invalid("a case needs case_id, photo_sha256, truth (and optional conditions)")
        if not isinstance(case["case_id"], str) or not _ID.fullmatch(case["case_id"]) or case["case_id"] in ids:
            raise Invalid("case ids must be short and unique")
        if not isinstance(case["photo_sha256"], str) or not _HEX64.fullmatch(case["photo_sha256"]) or case["photo_sha256"] in photos:
            raise Invalid(f"case {case['case_id']}: photo_sha256 must be unique 64-hex (the same photo cannot be counted twice)")
        ids.add(case["case_id"])
        photos.add(case["photo_sha256"])
        truth = case["truth"]
        if not isinstance(truth, dict) or set(truth) != set(CATEGORIES):
            raise Invalid(f"case {case['case_id']}: truth needs material, missing-step and defect (empty lists are fine)")
        for cat in CATEGORIES:
            if not set(_labels(truth[cat], f"case {case['case_id']} truth.{cat}")) <= set(vocab[cat]):
                raise Invalid(f"case {case['case_id']}: a {cat} label is not in the vocabulary")
        _labels(case.get("conditions", []), f"case {case['case_id']} conditions")
    return dataset


def checked_submission(submission, dataset) -> dict:
    if not isinstance(submission, dict) or set(submission) != {"model_id", "prompt_sha256", "predictions"}:
        raise Invalid("a submission has model_id, prompt_sha256 and predictions")
    if not isinstance(submission["model_id"], str) or not submission["model_id"].strip() or len(submission["model_id"]) > 512:
        raise Invalid("model_id is missing")
    if not isinstance(submission["prompt_sha256"], str) or not _HEX64.fullmatch(submission["prompt_sha256"]):
        raise Invalid("prompt_sha256 must be 64 hex characters")
    vocab = dataset["vocabulary"]
    case_ids = {c["case_id"] for c in dataset["cases"]}
    seen, covered = set(), set()
    for p in submission["predictions"] if isinstance(submission["predictions"], list) else [None]:
        if not isinstance(p, dict) or set(p) != {"case_id", "category", "label", "status", "confidence_permille"}:
            raise Invalid("a prediction has case_id, category, label, status and confidence_permille")
        if p["case_id"] not in case_ids or p["category"] not in CATEGORIES or p["label"] not in vocab[p["category"]] or p["status"] not in STATUSES:
            raise Invalid(f"prediction for {p['case_id']!r}: unknown case, category, label or status")
        c = p["confidence_permille"]
        if (p["status"] == "abstain" and c is not None) or (p["status"] == "found" and (type(c) is not int or not 0 <= c <= 1000)):
            raise Invalid(f"prediction for {p['case_id']}/{p['label']}: confidence must be 0..1000 when found and null when abstaining")
        key = (p["case_id"], p["category"], p["label"])
        if key in seen:
            raise Invalid(f"two predictions for {key[0]}/{key[2]}")
        seen.add(key)
        covered.add(p["case_id"])
    if covered != case_ids:
        raise Invalid("cases with no finding or abstention: " + ", ".join(sorted(case_ids - covered)) + " (every photo must be answered)")
    return submission


def checked_thresholds(thresholds) -> dict | None:
    if thresholds is None:
        return None
    if not isinstance(thresholds, dict) or not set(thresholds) <= set(CATEGORIES):
        raise Invalid("thresholds are per category: material, missing-step, defect")
    for cat, t in thresholds.items():
        if not isinstance(t, dict) or set(t) != {"min_precision_permille", "min_recall_permille", "min_present"} \
                or any(type(v) is not int or v < 0 for v in t.values()) or t["min_precision_permille"] > 1000 or t["min_recall_permille"] > 1000:
            raise Invalid(f"thresholds.{cat} needs whole min_precision_permille, min_recall_permille (0..1000) and min_present")
    return thresholds


def _rate(k: int, n: int) -> dict | None:
    w = wilson_permille(k, n)
    return None if w is None else {"permille": w[0], "lower_permille": w[1], "upper_permille": w[2], "of": n}


def _category(cat: str, dataset: dict, by_case: dict, thresholds: dict | None) -> dict:
    tp = fp = fn = tn = abstained = items = present = 0
    wrong: list[dict] = []
    for case in dataset["cases"]:
        truth = set(case["truth"][cat])
        for label in dataset["vocabulary"][cat]:
            items += 1
            pred = by_case.get(case["case_id"], {}).get((cat, label))
            is_present = label in truth
            present += is_present
            if pred == "abstain":
                abstained += 1
            if is_present:
                if pred == "found":
                    tp += 1
                else:
                    fn += 1
                    wrong.append({"case_id": case["case_id"], "label": label, "kind": "abstained-present" if pred == "abstain" else "missed"})
            elif pred == "found":
                fp += 1
                wrong.append({"case_id": case["case_id"], "label": label, "kind": "false-positive"})
            else:
                tn += 1
    precision, recall = _rate(tp, tp + fp), _rate(tp, present)
    reasons: list[str] = []
    t = (thresholds or {}).get(cat)
    if t is None:
        reasons.append("no thresholds were set by the owner for this category")
    else:
        if present < t["min_present"]:
            reasons.append(f"only {present} present labels, the owner's minimum is {t['min_present']}")
        if precision is None or precision["lower_permille"] < t["min_precision_permille"]:
            reasons.append(f"precision lower bound {None if precision is None else precision['lower_permille']} is under {t['min_precision_permille']} permille")
        if recall is None or recall["lower_permille"] < t["min_recall_permille"]:
            reasons.append(f"recall lower bound {None if recall is None else recall['lower_permille']} is under {t['min_recall_permille']} permille")
    return {"items": items, "present": present, "true_positive": tp, "false_positive": fp, "missed": fn, "true_negative": tn,
            "abstained": abstained, "precision": precision, "recall": recall, "abstain_rate": _rate(abstained, items),
            "status": "validated" if not reasons else "not-validated", "reasons": reasons,
            "wrong": sorted(wrong, key=lambda w: (w["case_id"], w["label"]))}


def evaluate(dataset, submission, thresholds=None, now=now_ms) -> dict:
    """The measured results for one model, prompt and labelled set. Raises Invalid for anything unusable."""
    dataset = checked_set(dataset)
    submission = checked_submission(submission, dataset)
    thresholds = checked_thresholds(thresholds)
    by_case: dict[str, dict] = {}
    for p in submission["predictions"]:
        by_case.setdefault(p["case_id"], {})[(p["category"], p["label"])] = p["status"]
    conditions: dict[str, int] = {}
    for case in dataset["cases"]:
        for c in case.get("conditions", []):
            conditions[c] = conditions.get(c, 0) + 1
    dataset_sha = sha256_of(dataset)
    predictions = sorted(submission["predictions"], key=lambda p: (p["case_id"], p["category"], p["label"]))
    run_id = sha256_of({"dataset_sha256": dataset_sha, "model_id": submission["model_id"], "prompt_sha256": submission["prompt_sha256"],
                        "predictions": predictions, "thresholds": thresholds})
    return {"run_version": RUN_VERSION, "run_id": run_id, "created_at_ms": now(), "model_id": submission["model_id"],
            "prompt_sha256": submission["prompt_sha256"], "dataset_sha256": dataset_sha, "n_photos": len(dataset["cases"]),
            "conditions_tested": dict(sorted(conditions.items())), "thresholds": thresholds,
            "categories": {cat: _category(cat, dataset, by_case, thresholds) for cat in CATEGORIES},
            "signed": False}


def _pct(rate: dict | None) -> str:
    return "n/a (no cases)" if rate is None else f"{rate['permille'] / 10:.1f}% (95% interval {rate['lower_permille'] / 10:.1f} to {rate['upper_permille'] / 10:.1f}, of {rate['of']})"


def report_lines(run: dict) -> list[str]:
    """Plain text for a person. States numbers and conditions; never says 'reliable'."""
    lines = [f"run {run['run_id'][:16]}…  model {run['model_id']}  {run['n_photos']} photos",
             "tested on: " + (", ".join(f"{k} x{v}" for k, v in run["conditions_tested"].items()) or "(no condition tags)"),
             "These numbers are for this model, this prompt and these photos only."]
    for cat, r in run["categories"].items():
        lines.append(f"{cat.upper()}: {r['status'].upper().replace('-', ' ')}")
        lines.append(f"  precision {_pct(r['precision'])}")
        lines.append(f"  recall    {_pct(r['recall'])}")
        lines.append(f"  abstained {_pct(r['abstain_rate'])}")
        lines.append(f"  {r['true_positive']} right, {r['false_positive']} wrong claims, {r['missed']} missed (of {r['present']} present)")
        lines += [f"  not validated because: {x}" for x in r["reasons"]]
        lines += [f"  {w['kind']}: {w['case_id']} / {w['label']}" for w in r["wrong"]]
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score an AI's inspection findings against a labelled photo set.")
    ap.add_argument("dataset", help="inspection_eval_set.v1 JSON")
    ap.add_argument("submission", help="model_id, prompt_sha256 and predictions JSON")
    ap.add_argument("--thresholds", help="JSON of the owner's per-category pass bar (omit: everything stays not-validated)")
    ap.add_argument("--out", help="write the run JSON here")
    args = ap.parse_args(argv)
    try:
        loaded = []
        for path in (args.dataset, args.submission, args.thresholds):
            if path is None:
                loaded.append(None)
            else:
                with open(path, encoding="utf-8") as fh:
                    loaded.append(json.load(fh))
        run = evaluate(loaded[0], loaded[1], loaded[2])
    except (Invalid, OSError, ValueError) as exc:
        print(f"cannot evaluate: {exc}", file=sys.stderr)
        return 2
    print("\n".join(report_lines(run)))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(run, fh, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
