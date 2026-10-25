# Offline checker for the app's exports

`verifier/shield_vault_verify.py` checks the two files the Shield app exports, with no network and without importing any Shield code:

- a **photo bundle** (`.shield.json`): `{ version, record, originalB64, devicePublicKey }`
- a **close-out packet** (`.shield-record.json`): the packet body plus `integrity: { hash, signature }`

(`verifier/shield_verify.py` is the separate checker for the records the phone uploads to the server; see `docs/RECORD_SPEC.md`.)

```
python verifier/shield_vault_verify.py photo.shield.json
python verifier/shield_vault_verify.py closeout.shield-record.json --signer 1A2B3C4D·5E6F7A8B
```

Standard library only, except the signature checks, which need `cryptography`. Without it they print `NOT CHECKED` and the exit code is 3, never a pass.
Exit codes: `0` every check ran and passed, `2` a check failed or the file is unreadable, `3` nothing failed but a signature check could not run.

## The written format

- **Canonical form.** JSON, object keys sorted, no spaces, strings not escaped beyond JSON's own rules, numbers written the way JavaScript's `JSON.stringify` writes them (`5.0` is `5`, `1e-7` is `1e-7`, `1e21` is `1e+21`).
- **Record hash.** SHA-256 of the canonical record without `signature` and `chainHead`.
- **Chain head.** SHA-256 of `prevChain + "|" + record hash`, as text.
- **Record signature.** ECDSA P-256 with SHA-256 over the canonical record without `signature` (it includes `chainHead`). Written as 64 raw bytes `r||s`, base64.
- **Seal ID.** SHA-256 of the raw public key; first 16 hex characters as `XXXXXXXX·XXXXXXXX`, upper case.
- **Packet.** `integrity.hash` is SHA-256 of the canonical packet without `integrity`; `integrity.signature` is the device signature over the same canonical text.

## What it checks

Bundle: the photo bytes match the signed `sha256`; the seal ID belongs to the key; the chain head recomputes; the signature verifies; the capture kind is the native camera.
Packet: the packet hash and signature; each sealed record as above; every record belongs to the packet's job and its point; no duplicate or forked records; the chain is in time order; the packet closed after every photo; no time ahead of this computer's clock by more than five minutes; the counts add up.

## What it does not check

- **Who holds the key.** Pass `--signer` with a seal ID you got from the photographer another way to pin it; otherwise the signer is only reported.
- **The photographer's note and ID-check receipt.** Those need the service's receipt keys; the app's Verify tab checks them. The tool says `NOT CHECKED`.
- **Device attestation.** The token is not in the export, so the tool cannot check it.
- That the scene is true, or the time beyond what the phone's clock said.

## Keeping it honest

`server/tests/vectors/vault-v1.json` was made by the app's own sealing code and frozen. The app's tests (Tradeneck `shield-app/src/verify/vault-vectors.test.ts`) check the same file with the app's code; `server/tests/test_vault_verifier.py` checks it with this tool and then tampers with every field kind. If the canonical format changes on purpose, regenerate the vectors and update both repos.
