"""The evaluation harness counts correctly per label, uses interval lower bounds, treats photos from one job as dependent, separates tuning
from testing, and fails closed. No model is called: predictions are synthetic."""
import copy
import json

import pytest

from app import inspection_eval as ev

H = lambda n: f"{n:064x}"
VOCAB = {"material": ["lumber", "rebar"], "missing-step": ["anchor-bolts"], "defect": ["honeycomb"]}
BAR = {"material": {"min_precision_permille": 900, "min_recall_permille": 900, "min_present": 30}}


def case(i, material=(), step=(), defect=(), conditions=("concrete",), group=None, split=None):
    c = {"case_id": f"c{i}", "photo_sha256": H(i + 1), "conditions": list(conditions),
         "truth": {"material": list(material), "missing-step": list(step), "defect": list(defect)}}
    if group is not None:
        c["group"] = group
    if split is not None:
        c["split"] = split
    return c


def dataset(cases):
    return {"dataset_version": 1, "vocabulary": copy.deepcopy(VOCAB), "cases": cases}


def pred(case_id, category, label, status="found", confidence=800):
    return {"case_id": case_id, "category": category, "label": label, "status": status,
            "confidence_permille": None if status == "abstain" else confidence}


def submission(preds, model="stub-model", prompt=999):
    return {"model_id": model, "prompt_sha256": H(prompt), "predictions": preds}


def run(cases, preds, thresholds=None, **kw):
    return ev.evaluate(dataset(cases), submission(preds), thresholds, now=lambda: 1, **kw)


def clean_cases(n=40, jobs=None):
    """n test photos that all show lumber; `jobs` photos per... jobs = number of distinct jobs (default one job per photo)."""
    return [case(i, material=["lumber"], group=f"j{i % (jobs or n)}", split="test") for i in range(n)]


def clean_run(n=40, jobs=None, thresholds=BAR, **kw):
    cases = clean_cases(n, jobs)
    return run(cases, [pred(c["case_id"], "material", "lumber") for c in cases], thresholds, split="test", prior_test_uses=set(), **kw)


def test_wilson_intervals_are_whole_permille_rounded_outward():
    assert ev.wilson_permille(0, 0) is None
    assert ev.wilson_permille(40, 40) == (1000, 912, 1000)  # a perfect score on 40 still has a lower bound near 91%
    point, lower, upper = ev.wilson_permille(5, 10)
    assert point == 500 and 230 <= lower <= 240 and 760 <= upper <= 770
    assert ev.wilson_permille(0, 20)[1] == 0
    assert ev.wilson_permille(4.0, 4.0)[1] < 700  # a smaller effective sample gives a much lower floor


def test_every_kind_of_outcome_is_counted_per_label_and_listed():
    cases = [case(0, material=["lumber"]), case(1, material=["lumber", "rebar"]), case(2), case(3, material=["rebar"]), case(4)]
    preds = [
        pred("c0", "material", "lumber"),                         # right
        pred("c1", "material", "lumber"),                         # right; rebar missed (no finding)
        pred("c2", "material", "rebar"),                          # claimed, not there: wrong
        pred("c3", "material", "rebar", status="abstain"),        # present but abstained: counts as missed
        pred("c4", "material", "lumber", status="abstain"),       # absent and abstained: not an error
    ]
    labels = run(cases, preds)["categories"]["material"]["labels"]
    lumber, rebar = labels["lumber"], labels["rebar"]
    assert (lumber["true_positive"], lumber["false_positive"], lumber["missed"], lumber["present"], lumber["abstained"]) == (2, 0, 0, 2, 1)
    assert (rebar["true_positive"], rebar["false_positive"], rebar["missed"], rebar["present"], rebar["abstained"]) == (0, 1, 2, 2, 1)
    assert rebar["precision"]["of"] == 1 and rebar["recall"]["of"] == 2 and lumber["abstain_rate"]["of"] == 5
    assert {(w["case_id"], w["kind"]) for w in rebar["wrong"]} == {("c1", "missed"), ("c2", "false-positive"), ("c3", "abstained-present")}


def test_a_label_nobody_asserted_has_no_precision_not_a_perfect_one():
    cases = [case(0, defect=["honeycomb"]), case(1)]
    d = run(cases, [pred("c0", "material", "lumber", "abstain"), pred("c1", "material", "lumber", "abstain")])["categories"]["defect"]["labels"]["honeycomb"]
    assert d["precision"] is None and d["recall"]["permille"] == 0 and d["status"] == "not-validated"


def test_a_strong_label_cannot_hide_a_weak_one():
    cases = [case(i, material=["lumber", "rebar"], group=f"j{i}", split="test") for i in range(40)]
    preds = [pred(c["case_id"], "material", "lumber") for c in cases]  # lumber always right, rebar never found
    out = run(cases, preds, BAR, split="test", prior_test_uses=set())["categories"]["material"]
    assert out["labels"]["lumber"]["status"] == "validated" and out["labels"]["rebar"]["status"] == "not-validated"
    assert out["validated_labels"] == ["lumber"] and out["status"] == "partly-validated"
    assert any("recall lower bound 0" in r for r in out["labels"]["rebar"]["reasons"])


def test_nothing_is_validated_without_thresholds_however_good():
    out = clean_run(thresholds=None)
    for cat in ev.CATEGORIES:
        assert out["categories"][cat]["status"] == "not-validated"
    lumber = out["categories"]["material"]["labels"]["lumber"]
    assert lumber["precision"]["permille"] == 1000 and "no thresholds were set by the owner" in lumber["reasons"][0]


def test_the_lower_bound_not_the_point_estimate_decides():
    assert clean_run()["categories"]["material"]["labels"]["lumber"]["status"] == "validated"
    under = clean_run(thresholds={"material": {**BAR["material"], "min_precision_permille": 950}})["categories"]["material"]["labels"]["lumber"]
    assert under["status"] == "not-validated" and any("precision lower bound 912" in x for x in under["reasons"])  # perfect 40/40, floor 912
    few = clean_run(thresholds={"material": {**BAR["material"], "min_present": 50}})["categories"]["material"]["labels"]["lumber"]
    assert few["status"] == "not-validated" and any("only 40 photos show it" in x for x in few["reasons"])


def test_photos_from_few_jobs_count_as_few_independent_samples():
    one_per_job = clean_run(jobs=40)
    four_jobs = clean_run(jobs=4)
    assert one_per_job["n_groups"] == 40 and four_jobs["n_groups"] == 4
    a, b = (r["categories"]["material"]["labels"]["lumber"]["precision"] for r in (one_per_job, four_jobs))
    assert a["effective_of"] == 40 and b["effective_of"] == 4 and b["of"] == 40
    assert b["lower_permille"] < 650 < a["lower_permille"]
    assert four_jobs["categories"]["material"]["labels"]["lumber"]["status"] == "not-validated"


def test_without_job_groups_nothing_validates():
    cases = [case(i, material=["lumber"], split="test") for i in range(40)]
    out = run(cases, [pred(c["case_id"], "material", "lumber") for c in cases], BAR, split="test", prior_test_uses=set())
    assert out["n_groups"] is None and any("no job grouping" in x for x in out["process_reasons"])
    assert out["categories"]["material"]["labels"]["lumber"]["status"] == "not-validated"


def test_tuning_photos_and_untracked_or_reused_test_sets_are_not_evidence():
    cases = [case(i, material=["lumber"], group=f"j{i}", split="tune" if i < 40 else "test") for i in range(80)]
    preds = [pred(c["case_id"], "material", "lumber") for c in cases]
    lumber = lambda out: out["categories"]["material"]["labels"]["lumber"]["status"]
    tune = run(cases, preds, BAR, split="tune")
    assert tune["n_photos"] == 40 and "scored on tuning photos: that is not evidence" in tune["process_reasons"] and lumber(tune) == "not-validated"
    untracked = run(cases, preds, BAR, split="test")
    assert any("not being tracked" in x for x in untracked["process_reasons"]) and lumber(untracked) == "not-validated"
    reused = run(cases, preds, BAR, split="test", prior_test_uses={("older-model", H(1))})
    assert any("already scored 1 other model or prompt" in x for x in reused["process_reasons"]) and lumber(reused) == "not-validated"
    same = run(cases, preds, BAR, split="test", prior_test_uses={("stub-model", H(999))})  # the same model and prompt again is a repeat, not tuning
    assert same["process_reasons"] == [] and lumber(same) == "validated"
    fresh = run(cases, preds, BAR, split="test", prior_test_uses=set())
    assert fresh["process_reasons"] == [] and lumber(fresh) == "validated"
    unsplit = run([case(i, material=["lumber"], group=f"j{i}") for i in range(40)], preds[:40], BAR)
    assert any("no tune/test split" in x for x in unsplit["process_reasons"]) and lumber(unsplit) == "not-validated"


def test_a_threshold_for_one_category_does_not_validate_the_others():
    out = clean_run()
    assert out["categories"]["defect"]["status"] == "not-validated" and out["categories"]["missing-step"]["status"] == "not-validated"


def test_the_set_and_submission_are_checked_closed():
    cases = [case(0, material=["lumber"]), case(1)]
    good = [pred("c0", "material", "lumber"), pred("c1", "material", "lumber", "abstain")]
    run(cases, good)
    with pytest.raises(ev.Invalid, match="every photo must be answered"):
        run(cases, good[:1])  # skipping a photo is not allowed
    for bad in (good + [pred("c0", "material", "lumber")],  # duplicate
                good + [pred("c9", "material", "lumber")],  # unknown case
                good + [pred("c0", "material", "glass")],   # unknown label
                good + [pred("c0", "defect", "lumber")],    # label from another category
                good + [pred("c0", "material", "rebar", confidence=1001)],
                good + [{**pred("c0", "material", "rebar", "abstain"), "confidence_permille": 500}],
                good + [{**pred("c0", "material", "rebar"), "status": "maybe"}],
                good + [{"case_id": "c0"}]):
        with pytest.raises(ev.Invalid):
            run(cases, bad)
    for bad_cases in ([case(0), case(0)],                       # duplicate case id
                      [case(0), {**case(1), "photo_sha256": H(1)}],  # same photo twice
                      [{**case(0), "truth": {"material": ["glass"], "missing-step": [], "defect": []}}],
                      [{**case(0), "photo_sha256": "xyz"}],
                      [case(0, group="j1"), case(1)],       # some cases grouped, some not
                      [case(0, split="test"), case(1)],
                      [{**case(0), "split": "validate"}],
                      [{**case(0), "group": "bad group"}],
                      []):
        with pytest.raises(ev.Invalid):
            run(bad_cases, good)
    with pytest.raises(ev.Invalid):
        ev.evaluate({**dataset(cases), "dataset_version": 2}, submission(good))
    with pytest.raises(ev.Invalid):
        run(cases, good, {"material": {"min_precision_permille": 1001, "min_recall_permille": 0, "min_present": 0}})
    with pytest.raises(ev.Invalid):
        run(cases, good, {"paint": {}})
    with pytest.raises(ev.Invalid, match="this set has no split"):
        run(cases, good, split="test")
    split_cases = [case(0, material=["lumber"], split="tune"), case(1, split="test")]
    with pytest.raises(ev.Invalid, match="say which one"):
        run(split_cases, good)
    with pytest.raises(ev.Invalid, match="no cases in the test split"):
        run([case(0, split="tune")], good[:1], split="test")


def test_only_the_scored_split_has_to_be_answered():
    cases = [case(0, material=["lumber"], split="tune"), case(1, split="test")]
    out = run(cases, [pred("c1", "material", "lumber", "abstain")], split="test")  # nothing about the tuning photo is needed
    assert out["n_photos"] == 1


def test_run_id_is_stable_and_changes_with_any_input():
    cases = [case(0, material=["lumber"]), case(1)]
    preds = [pred("c0", "material", "lumber"), pred("c1", "material", "lumber", "abstain")]
    a = ev.evaluate(dataset(cases), submission(preds), now=lambda: 1)
    assert a["run_id"] == ev.evaluate(dataset(cases), submission(list(reversed(preds))), now=lambda: 99)["run_id"]  # order and time do not matter
    assert a["run_id"] != run(cases, [pred("c0", "material", "lumber", confidence=799), preds[1]])["run_id"]
    assert a["run_id"] != ev.evaluate(dataset(cases), {**submission(preds), "model_id": "other"}, now=lambda: 1)["run_id"]
    assert a["run_id"] != run(cases, preds, {"material": {"min_precision_permille": 1, "min_recall_permille": 1, "min_present": 1}})["run_id"]
    split_cases = [case(0, material=["lumber"], split="tune"), case(1, split="tune")]
    assert run(split_cases, preds, split="tune")["run_id"] != run([case(0, material=["lumber"], split="test"), case(1, split="test")], preds, split="test")["run_id"]
    assert a["signed"] is False


def test_conditions_and_photo_count_are_reported():
    cases = [case(0, conditions=("concrete", "daylight")), case(1, conditions=("concrete",)), case(2, conditions=())]
    out = run(cases, [pred(c["case_id"], "material", "lumber", "abstain") for c in cases])
    assert out["n_photos"] == 3 and out["conditions_tested"] == {"concrete": 2, "daylight": 1}


def test_the_plain_report_is_per_label_states_its_limits_and_never_says_reliable():
    out = clean_run(thresholds=None)
    text = "\n".join(ev.report_lines(out))
    assert "only for the labels listed below" in text and "not on the list is not scored" in text
    assert "lumber: NOT VALIDATED; shown in 40 photos; precision 100.0% (91.2 to 100.0, of 40)" in text
    assert "tested on: concrete x40" in text and "from 40 jobs" in text and "[test split]" in text
    assert "reliable" not in text.lower()


def test_the_command_line_and_the_test_set_ledger(tmp_path, capsys):
    cases = [case(i, material=["lumber"], group=f"j{i}", split="test") for i in range(2)]
    p = {n: tmp_path / f"{n}.json" for n in ("set", "sub", "sub2", "out")}
    ledger = tmp_path / "ledger.jsonl"
    p["set"].write_text(json.dumps(dataset(cases)))
    preds = [pred("c0", "material", "lumber"), pred("c1", "material", "lumber", "abstain")]
    p["sub"].write_text(json.dumps(submission(preds)))
    p["sub2"].write_text(json.dumps(submission(preds, model="other-model")))
    base = [str(p["set"]), str(p["sub"]), "--split", "test", "--ledger", str(ledger)]
    assert ev.main(base + ["--out", str(p["out"])]) == 0
    assert json.loads(p["out"].read_text())["process_reasons"] == []  # first model on a fresh test set
    capsys.readouterr()
    assert ev.main([str(p["set"]), str(p["sub2"]), "--split", "test", "--ledger", str(ledger)]) == 0
    assert "already scored 1 other model or prompt" in capsys.readouterr().out
    assert len(ledger.read_text().splitlines()) == 2
    assert ev.main([str(p["set"]), str(p["sub"]), "--split", "test"]) == 0  # no ledger: reuse cannot be checked
    assert "not being tracked" in capsys.readouterr().out
    assert ev.main([str(p["set"]), str(p["sub"])]) == 2  # the set has splits: must say which
    assert "say which one" in capsys.readouterr().err
    assert ev.main([str(tmp_path / "missing.json"), str(p["sub"])]) == 2
