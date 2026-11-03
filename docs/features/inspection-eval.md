# Inspection AI evaluation harness (scoring only)

**Status: the scoring code exists (`server/app/inspection_eval.py`). No model is called, there is no labelled photo set yet, and so there are no real results.** Nothing in Shield may say the AI recognizes materials, missing steps or defects until a run on real labelled photos supports the sentence, and then only for the conditions that run covered.

## What goes in

1. **The labelled set** (`inspection_eval_set.v1`, JSON). A `vocabulary` of labels for each category (`material`, `missing-step`, `defect`) and a list of `cases`. A case is one photo (`photo_sha256`, unique: the same photo cannot be counted twice), a `truth` listing the labels that are really present per category (empty lists are fine), and optional `conditions` tags such as `concrete` or `daylight`. The owner labels these; keep them apart from real job records.
2. **A submission**: `model_id`, `prompt_sha256` and `predictions`, each `{case_id, category, label, status, confidence_permille}`. `status` is `found` or `abstain`; confidence is 0 to 1000 when found and `null` when abstaining. Every photo must have at least one prediction (an abstention counts), so a model cannot look better by skipping hard photos.
3. **Thresholds** (optional, the owner's): per category `min_precision_permille`, `min_recall_permille`, `min_present`.

## What comes out

Per category: right and wrong claims, missed labels, abstentions, **precision**, **recall** and **abstain rate** with 95% Wilson intervals (whole permille, rounded outward), and the list of every wrong or missed pair (`false-positive`, `missed`, `abstained-present`). An abstention on a label that is present counts as missed for recall; it is also shown in the abstain rate. A category nobody asserted anything in has no precision (`null`), not a perfect one.

The run also records `n_photos`, `conditions_tested`, the model id, the prompt hash, the set's hash and a content-addressed `run_id` (hash of the set, model, prompt, predictions and thresholds; the same inputs give the same id). It is **not signed yet**, and the AI block's `evaluation_run_id` is not linked to it yet.

## Fails closed

A category is `validated` only when the owner's thresholds are met by the interval's **lower bound**, not the point estimate, on at least `min_present` present labels. With no thresholds, too few labels or a low bound it is `not-validated` and the reasons are listed. A perfect 40 of 40 still has a lower bound near 91%, so it fails a 95% bar. Thresholds are set by the owner after seeing results; nothing here picks them.

## What a result is

The numbers for this model, this prompt and this set of photos. They say nothing about other photos, other lighting or trades, or a changed model; re-run after any change. The plain-text report states the photo count and conditions tested and never uses the word "reliable".

```
python -m app.inspection_eval set.json submission.json [--thresholds bar.json] [--out run.json]   # from server/
```

## Not built yet

- The live model call that produces a submission (`SHIELD_AI_ENABLED`, off by default; sends a stored photo to a model provider, needs the owner's go, an API key on Render and a privacy-policy sentence).
- It will need each finding to carry the vocabulary `label` it is about. `ai_findings.v1` has no such field yet; it is unused anywhere live, so it can be added then.
- Signing a run and linking it from the AI block; the app screens.
