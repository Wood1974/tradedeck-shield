# Inspection report: AI findings and human approval (format only)

**Status: the format, the signing and the offline checker exist. No AI is called anywhere yet, no route serves a report, and nothing here claims the AI is reliable.** Calling a model, measuring it and the app screens are later steps (see "Not built").

A report keeps three things apart and never merges them into one verdict:

1. **Photo integrity.** The hardware-signed record, hash chain, Apple evidence and time. Checked by `verifier/shield_verify.py`, `shield_vault_verify.py` and `shield_apple_verify.py`. The report only names the photo and record (`integrity.photo_sha256`, `integrity.record_hash`, optionally the phone key).
2. **AI findings** (`ai_findings.v1`, `server/app/inspection_report.py`). Each finding has an `id`, a `category` (`material`, `missing-step` or `defect`), a `status` (`found` or `abstain`), plain `text` (at most 500 characters) and `confidence_permille` (0 to 1000, whole numbers; `null` for an abstention, whose text says why). Abstaining is a normal answer. The block also carries the photo hash, record hash, `checkpoint_context_sha256`, `model_id`, `prompt_sha256`, `raw_output_sha256`, `created_at_ms`, the signing key id and `evaluation_run_id`. It is signed (ECDSA P-256 over canonical JSON) by the Shield **analysis key**, `SHIELD_ANALYSIS_SIGNING_KEY_PEM`, a separate key from the ticket key; without it signing is closed.
3. **Human approval** (`human_approval.v1`). For each finding the person decides `accepted` or `rejected`. Nothing else can be expressed: there is no edit and no replacement text. The phone's hardware key signs `"shield-approval-v1" || SHA256(canonical(approval))`, and the approval names the SHA-256 of the unchanged AI block. A finding can only be decided after it was shown (`effort.shown_finding_ids`); `effort.screen_ms` is recorded as a plain fact, not a quality claim. A finding with no decision is labelled **AI, not reviewed**.

## What the checker proves, and what it does not

`python verifier/shield_inspection_verify.py report.json --analysis-key <published public key, base64>`

Proves: the AI block is well formed; it is about the photo and record the report names; it was not changed since the holder of the signing key signed it (with `--analysis-key`, that holder is the key you pinned; without it, that line says NOT CHECKED); an approval, if present, is over exactly that block, decides only its findings, and was signed by the holder of its key.

Does **not** prove: that any finding is correct (the signature binds words to a photo; it says nothing about truth); that the AI is reliable (with `evaluation_run_id` null the checker prints "AI findings, not validated"; a named run is reported NOT CHECKED because its results are not in the file); that the approver is who they say they are; that the approver's key is held in phone hardware (that needs Apple evidence for that key).

Exit code: 0 nothing failed and nothing left unchecked; 2 a check failed; 3 nothing failed but something is missing or not checked (no approval, no pinned key, a named evaluation run).

## Not built (each its own step, owner's go for the ones that change what leaves the server or costs money)

- The evaluation harness (labelled photos, precision, recall and abstain rate with confidence intervals).
- The live model call, behind `SHIELD_AI_ENABLED` (off by default). It sends one stored photo to a model provider, only when the owner asks for it on that photo; it needs an API key set on Render and a privacy-policy sentence first.
- The app's "Run AI review" button and the separate AI and approval screens.
- Publishing the analysis public key at a route, like `GET /shield/tickets/key`.
