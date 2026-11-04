# Inspection AI evaluation harness (scoring only)

**Status: the scoring code exists (`server/app/inspection_eval.py`). No model is called, there is no labelled photo set yet, and so there are no real results.** Nothing in Shield may say the AI recognizes materials, missing steps or defects until a run on real labelled photos supports the sentence, and then only for the labels and conditions that run covered.

## What goes in

1. **The labelled set** (`inspection_eval_set.v1`, JSON). A `vocabulary` of labels for each category (`material`, `missing-step`, `defect`) and a list of `cases`. A case is one photo (`photo_sha256`, unique: the same photo cannot be counted twice), a `truth` listing the labels that are really present per category (empty lists are fine), and optional tags:
   - `conditions`: tags such as `concrete` or `daylight`.
   - `group`: the job the photo came from. Either every case has one or none does.
   - `split`: `tune` or `test`. Either every case has one or none does.
   The owner labels these (`eval/README.md`); keep them apart from real job records.
2. **A submission**: `model_id`, `prompt_sha256` and `predictions`, each `{case_id, category, label, status, confidence_permille}`. `status` is `found` or `abstain`; confidence is 0 to 1000 when found and `null` when abstaining. Every scored photo must have at least one prediction (an abstention counts), so a model cannot look better by skipping hard photos.
3. **Thresholds** (optional, the owner's): per category `min_precision_permille`, `min_recall_permille`, `min_present`. They apply to each label in the category.

## What comes out: per label, not per category

For every label: right and wrong claims, missed, abstentions, **precision**, **recall** and **abstain rate** with 95% Wilson intervals (whole permille, rounded outward), and the photos it got wrong (`false-positive`, `missed`, `abstained-present`). An abstention on a label that is present counts as missed for recall and also shows in the abstain rate. A label nobody asserted has no precision (`null`), not a perfect one. A category is `validated` only if every one of its labels is, `partly-validated` if some are, and the report names which. Results are per label because a claim is about one thing ("rebar"); pooling a category would let a label the AI always gets right hide one it never does.

## Fails closed

A label is `validated` only when all of these hold:
- The owner's thresholds are met by the interval's **lower bound**, not the point estimate, on at least `min_present` photos that show it. A perfect 40 of 40 still has a lower bound near 91%, so it fails a 95% bar.
- **Photos are treated as only as independent as the jobs they come from.** Photos from one job share a site, light and photographer. With `group` on every case, the interval is computed as if there were only as many photos as there are jobs (the cautious reading: 40 photos from 4 jobs count as 4). Without `group`, nothing validates.
- **The prompt was not tuned on the photos scored.** The set needs a `split`. `tune` runs are for improving the prompt and are not evidence. A `test` run is evidence only if the test set has not already scored a *different* model or prompt. The ledger (`--ledger`, a file of which model and prompt have scored which test set) tracks that; without it reuse cannot be checked and nothing validates. The ledger guards against accident, not against someone deleting the file.

## What a result is

The numbers for this model, this prompt, these photos and **only the labels on the list**. The scorer cannot say how the AI does on a defect or material that is not in the vocabulary; the report says so. It also says nothing about other photos, other lighting or trades, or a changed model; re-run after any change. The plain-text report states the photo and job counts and the conditions tested, and never uses the word "reliable".

The run is content-addressed (`run_id` hashes the set, model, prompt, predictions, thresholds and split; the same inputs give the same id). It is **not signed yet**, and the AI block's `evaluation_run_id` is not linked to it yet.

```
python -m app.inspection_eval set.json submission.json --split test --ledger ledger.jsonl [--thresholds bar.json] [--out run.json]   # from server/
```

## Not built yet

- The live model call that produces a submission (`SHIELD_AI_ENABLED`, off by default; sends a stored photo to a model provider, needs the owner's go, an API key and a privacy-policy sentence). Where the labelled photos are run from (a local script with the owner's own key, or a server route) is undecided.
- It will need each finding to carry the vocabulary `label` it is about (`ai_findings.v1` has no such field yet; it is unused live, so it can be added then), and a place for findings outside the vocabulary to be listed unscored for a person to read.
- The labelling converter does not write `group` or `split` yet (a follow-up to `eval/csv_to_set.py`).
- Checkpoint definitions (what steps are expected at each checkpoint), hashed into the AI block.
- Signing a run and linking it from the AI block; the app screens.
