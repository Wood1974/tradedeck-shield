"""The evaluation harness counts correctly, uses interval lower bounds, and fails closed. No model is called: predictions are synthetic."""
import copy
import json

import pytest

from app import inspection_eval as ev

H = lambda n: f"{n:064x}"
VOCAB = {"material": ["lumber", "rebar"], "missing-step": ["anchor-bolts"], "defect": ["honeycomb"]}


def case(i, material=(), step=(), defect=(), conditions=("concrete",)):
    return {"case_id": f"c{i}", "photo_sha256": H(i + 1), "conditions": list(conditions),
            "truth": {"material": list(material), "missing-step": list(step), "defect": list(defect)}}


def dataset(cases):
    return {"dataset_version": 1, "vocabulary": copy.deepcopy(VOCAB), "cases": cases}


def pred(case_id, category, label, status="found", confidence=800):
    return {"case_id": case_id, "category": category, "label": label, "status": status,
            "confidence_permille": None if status == "abstain" else confidence}


def submission(preds):
    return {"model_id": "stub-model", "prompt_sha256": H(999), "predictions": preds}


def run(cases, preds, thresholds=None):
    return ev.evaluate(dataset(cases), submission(preds), thresholds, now=lambda: 1)


def test_wilson_intervals_are_whole_permille_rounded_outward():
    assert ev.wilson_permille(0, 0) is None
    assert ev.wilson_permille(40, 40) == (1000, 912, 1000)  # a perfect score on 40 still has a lower bound near 91%
    point, lower, upper = ev.wilson_permille(5, 10)
    assert point == 500 and 230 <= lower <= 240 and 760 <= upper <= 770
    assert ev.wilson_permille(0, 20)[1] == 0


def test_every_kind_of_outcome_is_counted_and_listed():
    cases = [case(0, material=["lumber"]), case(1, material=["lumber", "rebar"]), case(2), case(3, material=["rebar"]), case(4)]
    preds = [
        pred("c0", "material", "lumber"),                         # right
        pred("c1", "material", "lumber"),                         # right; rebar missed (no finding)
        pred("c2", "material", "rebar"),                          # claimed, not there: wrong
        pred("c3", "material", "rebar", status="abstain"),        # present but abstained: counts as missed
        pred("c4", "material", "lumber", status="abstain"),       # absent and abstained: not an error
    ]
    m = run(cases, preds)["categories"]["material"]
    assert (m["true_positive"], m["false_positive"], m["missed"], m["abstained"], m["present"], m["items"]) == (2, 1, 2, 2, 4, 10)
    assert m["true_negative"] == 5
    assert m["precision"]["of"] == 3 and m["recall"]["of"] == 4 and m["abstain_rate"]["of"] == 10
    kinds = {(w["case_id"], w["label"]): w["kind"] for w in m["wrong"]}
    assert kinds == {("c1", "rebar"): "missed", ("c2", "rebar"): "false-positive", ("c3", "rebar"): "abstained-present"}


def test_a_category_nobody_answered_has_no_precision_not_a_perfect_one():
    cases = [case(0, defect=["honeycomb"]), case(1)]
    r = run(cases, [pred("c0", "material", "lumber", "abstain"), pred("c1", "material", "lumber", "abstain")])["categories"]["defect"]
    assert r["precision"] is None and r["recall"]["permille"] == 0 and r["status"] == "not-validated"


def test_with_no_thresholds_nothing_is_validated_however_good():
    cases = [case(i, material=["lumber"]) for i in range(40)]
    out = run(cases, [pred(c["case_id"], "material", "lumber") for c in cases])
    for cat in ev.CATEGORIES:
        assert out["categories"][cat]["status"] == "not-validated"
        assert "no thresholds were set by the owner" in out["categories"][cat]["reasons"][0]
    assert out["categories"]["material"]["precision"]["permille"] == 1000


def test_the_lower_bound_not_the_point_estimate_decides():
    cases = [case(i, material=["lumber"]) for i in range(40)]
    preds = [pred(c["case_id"], "material", "lumber") for c in cases]
    bar = lambda p, r, n: {"material": {"min_precision_permille": p, "min_recall_permille": r, "min_present": n}}
    assert run(cases, preds, bar(900, 900, 30))["categories"]["material"]["status"] == "validated"
    under = run(cases, preds, bar(950, 900, 30))["categories"]["material"]  # perfect 40/40, but the interval's floor is 912
    assert under["status"] == "not-validated" and any("precision lower bound 912" in x for x in under["reasons"])
    few = run(cases, preds, bar(900, 900, 50))["categories"]["material"]
    assert few["status"] == "not-validated" and any("only 40 present labels" in x for x in few["reasons"])


def test_a_threshold_for_one_category_does_not_validate_the_others():
    cases = [case(i, material=["lumber"]) for i in range(40)]
    out = run(cases, [pred(c["case_id"], "material", "lumber") for c in cases], {"material": {"min_precision_permille": 900, "min_recall_permille": 900, "min_present": 30}})
    assert out["categories"]["material"]["status"] == "validated"
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
                      []):
        with pytest.raises(ev.Invalid):
            run(bad_cases, good)
    with pytest.raises(ev.Invalid):
        ev.evaluate({**dataset(cases), "dataset_version": 2}, submission(good))
    with pytest.raises(ev.Invalid):
        run(cases, good, {"material": {"min_precision_permille": 1001, "min_recall_permille": 0, "min_present": 0}})
    with pytest.raises(ev.Invalid):
        run(cases, good, {"paint": {}})


def test_run_id_is_stable_and_changes_with_any_input():
    cases = [case(0, material=["lumber"]), case(1)]
    preds = [pred("c0", "material", "lumber"), pred("c1", "material", "lumber", "abstain")]
    a = ev.evaluate(dataset(cases), submission(preds), now=lambda: 1)
    assert a["run_id"] == ev.evaluate(dataset(cases), submission(list(reversed(preds))), now=lambda: 99)["run_id"]  # order and time do not matter
    assert a["run_id"] != run(cases, [pred("c0", "material", "lumber", confidence=799), preds[1]])["run_id"]
    assert a["run_id"] != ev.evaluate(dataset(cases), {**submission(preds), "model_id": "other"}, now=lambda: 1)["run_id"]
    assert a["run_id"] != run(cases, preds, {"material": {"min_precision_permille": 1, "min_recall_permille": 1, "min_present": 1}})["run_id"]
    assert a["signed"] is False


def test_conditions_and_photo_count_are_reported():
    cases = [case(0, conditions=("concrete", "daylight")), case(1, conditions=("concrete",)), case(2, conditions=())]
    out = run(cases, [pred(c["case_id"], "material", "lumber", "abstain") for c in cases])
    assert out["n_photos"] == 3 and out["conditions_tested"] == {"concrete": 2, "daylight": 1}


def test_the_plain_report_gives_numbers_and_conditions_and_never_says_reliable():
    cases = [case(i, material=["lumber"]) for i in range(5)]
    out = run(cases, [pred(c["case_id"], "material", "lumber") for c in cases])
    text = "\n".join(ev.report_lines(out))
    assert "for this model, this prompt and these photos only" in text and "tested on: concrete x5" in text
    assert "95% interval" in text and "NOT VALIDATED" in text
    assert "reliable" not in text.lower()


def test_the_command_line(tmp_path, capsys):
    cases = [case(0, material=["lumber"]), case(1)]
    paths = {n: tmp_path / f"{n}.json" for n in ("set", "sub", "bar", "out")}
    paths["set"].write_text(json.dumps(dataset(cases)))
    paths["sub"].write_text(json.dumps(submission([pred("c0", "material", "lumber"), pred("c1", "material", "lumber", "abstain")])))
    assert ev.main([str(paths["set"]), str(paths["sub"]), "--out", str(paths["out"])]) == 0
    assert json.loads(paths["out"].read_text())["categories"]["material"]["status"] == "not-validated"
    assert "NOT VALIDATED" in capsys.readouterr().out
    paths["sub"].write_text(json.dumps(submission([pred("c0", "material", "lumber")])))  # skips c1
    assert ev.main([str(paths["set"]), str(paths["sub"])]) == 2
    assert "every photo must be answered" in capsys.readouterr().err
    assert ev.main([str(tmp_path / "missing.json"), str(paths["sub"])]) == 2
