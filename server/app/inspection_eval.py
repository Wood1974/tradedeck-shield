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

Results are per LABEL ("rebar"), not per category: a claim is about one thing, and pooling labels lets a strong one hide a weak one.
Photos from one job are not independent (same site, same lighting, same photographer). If every case names its `group` (a job id),
the interval treats the photos as only as many independent samples as there are groups, which is the cautious reading; without
groups nothing can be validated. Cases may also carry `split` (`tune` or `test`): tune the prompt on `tune`, then score `test` once. A test
set that has already scored a different model or prompt is not a clean test, and a label cannot be validated on it.

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
SPLITS = ("tune", "test")
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


def wilson_permille(k: float, n: float) -> tuple[int, int, int] | None:
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
        if not isinstance(case, dict) or set(case) - {"case_id", "photo_sha256", "conditions", "truth", "group", "split"} or not {"case_id", "photo_sha256", "truth"} <= set(case):
            raise Invalid("a case needs case_id, photo_sha256, truth (and optional conditions, group, split)")
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
        if "group" in case and (not isinstance(case["group"], str) or not _ID.fullmatch(case["group"])):
            raise Invalid(f"case {case['case_id']}: group must be a short job id")
        if "split" in case and case["split"] not in SPLITS:
            raise Invalid(f"case {case['case_id']}: split must be tune or test")
    for field in ("group", "split"):
        if len({field in c for c in cases}) != 1:
            raise Invalid(f"either every case has a {field} or none does")
    return dataset


def checked_submission(submission, dataset, required=None) -> dict:
    if not isinstance(submission, dict) or set(submission) != {"model_id", "prompt_sha256", "predictions"}:
        raise Invalid("a submission has model_id, prompt_sha256 and predictions")
    if not isinstance(submission["model_id"], str) or not submission["model_id"].strip() or len(submission["model_id"]) > 512:
        raise Invalid("model_id is missing")
    if not isinstance(submission["prompt_sha256"], str) or not _HEX64.fullmatch(submission["prompt_sha256"]):
        raise Invalid("prompt_sha256 must be 64 hex characters")
    vocab = dataset["vocabulary"]
    case_ids = {c["case_id"] for c in dataset["cases"]}
    required = case_ids if required is None else required
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
    if not required <= covered:
        raise Invalid("cases with no finding or abstention: " + ", ".join(sorted(required - covered)) + " (every photo must be answered)")
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


def _rate(k: int, n: int, r: float = 1.0) -> dict | None:
    """A rate with its 95% interval. `r` (clusters / photos, at most 1) shrinks the sample the interval is computed from."""
    w = wilson_permille(k * r, n * r)
    return None if w is None else {"permille": w[0], "lower_permille": w[1], "upper_permille": w[2], "of": n, "effective_of": round(n * r, 2)}


def _label(cat: str, label: str, cases: list, by_case: dict, r: float, t: dict | None) -> dict:
    tp = fp = fn = abstained = present = 0
    wrong: list[dict] = []
    for case in cases:
        is_present = label in case["truth"][cat]
        pred = by_case.get(case["case_id"], {}).get((cat, label))
        present += is_present
        abstained += pred == "abstain"
        if is_present and pred == "found":
            tp += 1
        elif is_present:
            fn += 1
            wrong.append({"case_id": case["case_id"], "kind": "abstained-present" if pred == "abstain" else "missed"})
        elif pred == "found":
            fp += 1
            wrong.append({"case_id": case["case_id"], "kind": "false-positive"})
    precision, recall = _rate(tp, tp + fp, r), _rate(tp, present, r)
    reasons: list[str] = []
    if t is None:
        reasons.append("no thresholds were set by the owner for this category")
    else:
        if present < t["min_present"]:
            reasons.append(f"only {present} photos show it, the owner's minimum is {t['min_present']}")
        if precision is None or precision["lower_permille"] < t["min_precision_permille"]:
            reasons.append(f"precision lower bound {None if precision is None else precision['lower_permille']} is under {t['min_precision_permille']} permille")
        if recall is None or recall["lower_permille"] < t["min_recall_permille"]:
            reasons.append(f"recall lower bound {None if recall is None else recall['lower_permille']} is under {t['min_recall_permille']} permille")
    return {"photos": len(cases), "present": present, "true_positive": tp, "false_positive": fp, "missed": fn, "abstained": abstained,
            "precision": precision, "recall": recall, "abstain_rate": _rate(abstained, len(cases), r),
            "reasons": reasons, "wrong": sorted(wrong, key=lambda w: w["case_id"])}


def evaluate(dataset, submission, thresholds=None, now=now_ms, split=None, prior_test_uses=None) -> dict:
    """The measured results for one model, prompt and labelled set. Raises Invalid for anything unusable.

    `split` picks the cases to score when the set has splits ("tune" or "test"). `prior_test_uses` is the set of (model_id, prompt_sha256)
    pairs the ledger says have already scored this test set; None means reuse is not being tracked, which blocks validation."""
    dataset = checked_set(dataset)
    has_split = "split" in dataset["cases"][0]
    if has_split and split not in SPLITS:
        raise Invalid("this set has a tune/test split: say which one to score (tune or test)")
    if not has_split and split is not None:
        raise Invalid("this set has no split")
    cases = [c for c in dataset["cases"] if not has_split or c["split"] == split]
    if not cases:
        raise Invalid(f"no cases in the {split} split")
    submission = checked_submission(submission, dataset, {c["case_id"] for c in cases})
    thresholds = checked_thresholds(thresholds)
    by_case: dict[str, dict] = {}
    for p in submission["predictions"]:
        by_case.setdefault(p["case_id"], {})[(p["category"], p["label"])] = p["status"]
    grouped = "group" in cases[0]
    r = len({c["group"] for c in cases}) / len(cases) if grouped else 1.0
    process: list[str] = []
    if not grouped:
        process.append("no job grouping: photos from one job are not independent, and without groups the margins are too narrow")
    if not has_split:
        process.append("no tune/test split: the prompt may have been tuned on these photos")
    elif split == "tune":
        process.append("scored on tuning photos: that is not evidence")
    else:
        uses = None if prior_test_uses is None else set(prior_test_uses) | {(submission["model_id"], submission["prompt_sha256"])}
        if uses is None:
            process.append("test-set reuse is not being tracked (no ledger)")
        elif len(uses) > 1:
            process.append(f"this test set has already scored {len(uses) - 1} other model or prompt: not a clean test")
    conditions: dict[str, int] = {}
    for case in cases:
        for c in case.get("conditions", []):
            conditions[c] = conditions.get(c, 0) + 1
    dataset_sha = sha256_of(dataset)
    predictions = sorted(submission["predictions"], key=lambda p: (p["case_id"], p["category"], p["label"]))
    run_id = sha256_of({"dataset_sha256": dataset_sha, "model_id": submission["model_id"], "prompt_sha256": submission["prompt_sha256"],
                        "predictions": predictions, "thresholds": thresholds, "split": split})
    categories = {}
    for cat in CATEGORIES:
        labels = {lab: _label(cat, lab, cases, by_case, r, (thresholds or {}).get(cat)) for lab in dataset["vocabulary"][cat]}
        for entry in labels.values():
            entry["status"] = "validated" if not entry["reasons"] and not process else "not-validated"
        ok = [lab for lab, e in labels.items() if e["status"] == "validated"]
        categories[cat] = {"labels": labels, "validated_labels": ok,
                           "status": "validated" if len(ok) == len(labels) else ("partly-validated" if ok else "not-validated")}
    return {"run_version": RUN_VERSION, "run_id": run_id, "created_at_ms": now(), "model_id": submission["model_id"],
            "prompt_sha256": submission["prompt_sha256"], "dataset_sha256": dataset_sha, "split": split, "n_photos": len(cases),
            "n_groups": len({c["group"] for c in cases}) if grouped else None, "conditions_tested": dict(sorted(conditions.items())),
            "thresholds": thresholds, "process_reasons": process, "categories": categories, "signed": False}


def _pct(rate: dict | None) -> str:
    if rate is None:
        return "n/a"
    return f"{rate['permille'] / 10:.1f}% ({rate['lower_permille'] / 10:.1f} to {rate['upper_permille'] / 10:.1f}, of {rate['of']})"


def report_lines(run: dict) -> list[str]:
    """Plain text for a person. States numbers and conditions; never says 'reliable'."""
    lines = [f"run {run['run_id'][:16]}...  model {run['model_id']}  {run['n_photos']} photos" + (f" from {run['n_groups']} jobs" if run["n_groups"] else "")
             + (f"  [{run['split']} split]" if run["split"] else ""),
             "tested on: " + (", ".join(f"{k} x{v}" for k, v in run["conditions_tested"].items()) or "(no condition tags)"),
             "These numbers are for this model, this prompt and these photos only, and only for the labels listed below.",
             "Anything the AI sees that is not on the list is not scored here."]
    lines += [f"not evidence yet: {x}" for x in run["process_reasons"]]
    for cat, c in run["categories"].items():
        lines.append(f"{cat.upper()}: {c['status'].upper().replace('-', ' ')} ({len(c['validated_labels'])} of {len(c['labels'])} labels)")
        for lab, e in c["labels"].items():
            lines.append(f"  {lab}: {e['status'].upper().replace('-', ' ')}; shown in {e['present']} photos; precision {_pct(e['precision'])}; "
                         f"recall {_pct(e['recall'])}; abstained {_pct(e['abstain_rate'])}")
            lines += [f"      not validated because: {x}" for x in e["reasons"]]
            lines += [f"      {w['kind']}: {w['case_id']}" for w in e["wrong"]]
    return lines


def _ledger_read(path: str, dataset_sha: str) -> set[tuple[str, str]]:
    """The (model, prompt) pairs already scored on this test set. A missing file means none. It guards against accident, not against deleting the file."""
    try:
        with open(path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
    except FileNotFoundError:
        return set()
    return {(r["model_id"], r["prompt_sha256"]) for r in rows if r.get("dataset_sha256") == dataset_sha}


def _ledger_add(path: str, dataset_sha: str, model_id: str, prompt_sha: str) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"dataset_sha256": dataset_sha, "model_id": model_id, "prompt_sha256": prompt_sha}, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score an AI's inspection findings against a labelled photo set.")
    ap.add_argument("dataset", help="inspection_eval_set.v1 JSON")
    ap.add_argument("submission", help="model_id, prompt_sha256 and predictions JSON")
    ap.add_argument("--thresholds", help="JSON of the owner's per-category pass bar (omit: everything stays not-validated)")
    ap.add_argument("--split", choices=SPLITS, help="which split to score, when the set has tune and test cases")
    ap.add_argument("--ledger", help="file that remembers which models and prompts have scored a test set (needed to validate on it)")
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
        prior = _ledger_read(args.ledger, sha256_of(loaded[0])) if args.ledger and args.split == "test" else None
        run = evaluate(loaded[0], loaded[1], loaded[2], split=args.split, prior_test_uses=prior)
        if prior is not None:
            _ledger_add(args.ledger, run["dataset_sha256"], run["model_id"], run["prompt_sha256"])
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
