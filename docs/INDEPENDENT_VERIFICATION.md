# Section 10 — Independent Verification

Shield verification is a separate read/check path. It never trusts a capture UI's "valid" label.

## Inputs

`POST /shield/v1/verify` requires an Evidence ID. A verifier may additionally provide:

- the alleged original JPEG bytes;
- the human `location_stated` and `purpose` attestation fields.

The public verification response intentionally excludes account identity, raw device location, platform-attestation payloads, and the stored original.

## Checks

The verifier independently:

1. re-hashes the server-held original and compares it with the sealed photo SHA-256;
2. if a file is supplied, hashes those exact supplied bytes and compares them with the sealed hash;
3. if testimony is supplied, canonicalizes it under `shield-evidence-v1` and recomputes the note SHA-256;
4. recomputes the bind hash from photo hash + note hash + job + point + nonce + account binding;
5. checks that the current evidence state is a sealed lineage state and agrees with append-only state history;
6. checks the sealed custody event against the stored photo, note, and bind hashes.

An authenticated owner endpoint remains at `GET /shield/evidence/{evidence_id}/verify`.

## Meaning of `ok`

`ok=true` means the checked material is cryptographically consistent with the Shield record and its custody metadata. It does **not** prove that a human statement is true, does not mean "GPS verified," and does not provide a trusted third-party timestamp. RFC 3161 timestamping is Section 16.

## Privacy

Independent verification is deliberately narrow. Evidence ID is a high-entropy identifier, and the verifier returns verification facts rather than private capture metadata.
