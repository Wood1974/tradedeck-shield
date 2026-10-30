# Apple's evidence, kept and re-checkable

Until now the server verified Apple's attestation (when a phone enrols) and Apple's assertion (when a photo arrives) and kept only its verdict. A verdict is the server's word. This keeps what Apple actually signed, so someone else can check it.

## What is kept
- **Per phone key** (`attestation_evidence` table, `server/app/attestation_evidence.py`): the attestation object (Apple's certificate chain is inside it), the challenge it was made over, the app id and environment. Kept at enrolment, once per key.
- **Per photo** (`captures.attest_assertion_b64`): the assertion bytes the phone sent, stored beside the signed record, not inside it.

Keys enrolled and photos uploaded before this have none of it. They keep working; their evidence reads `kept: false` with the reason. A phone key enrolled before this change needs enrolling again to get evidence for new photos (the app has no re-enrol button; not built unasked).

## Fetching it
`GET /shield/captures/{record_hash}/evidence`, signed-in account that owns the photo only (another account, or a bad hash, gets 404). Returns the record, its signature and key, `apple` (kept or not, why, and the parts), and the outside time-stamp reply if one covers the photo.

## Checking it without Shield
```
pip install cryptography cbor2
python verifier/shield_apple_verify.py evidence.json --root Apple_App_Attestation_Root_CA.pem [--at <time the key enrolled>]
```
Get the root from Apple, not from this repo (the checker prints the root's SHA-256 so you can compare). It checks: the chain ends at that root; the certificate's nonce matches the challenge; the key id is the hash of the attested key; the app id; the attestation counter and App Attest AAGUID (production or sandbox); and that the attested key signed this photo's record hash. Each line says CHECKED, FAILED or NOT CHECKED. Exit 0 pass, 2 failed, 3 evidence not kept.

Never a pass: certificate validity (only judged if you pass `--at`, because the key certificate is short-lived) and that the assertion counter only increases (needs every assertion from the key; the server tracks it).

## Not verified
Apple's real chain has never been run through this code or this checker. Tests use a synthetic Apple-style chain (`server/tests/test_attest_chain.py`, `test_apple_evidence.py`). The first real iPhone enrolment after this is deployed is the real test: enrol, take a photo, fetch the evidence, run the checker against Apple's published root.

## Clock note (same change)
`time_audit.assess` takes `anchored` (a server ticket started the chain). Checked by running it: a clock set back before the chain, two photos in one boot, no GPS time, reads CONSISTENT. The label is unchanged (the app reads it); without an anchor the notes now say the date is the phone's word, and a photo days older than its upload says so too. Never a mismatch for that alone: photos wait for signal.
