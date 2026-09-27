# TradeDeck Shield API — Section 5

Section 5 makes the Shield API the authoritative server boundary between native capture clients and evidence custody.

## Authority rules

- In production, every protected request requires `Authorization: Bearer <Supabase access token>`.
- The server verifies the Supabase JWT signature, issuer, audience, expiration, and subject using the project's JWKS endpoint.
- `sub` is the authoritative `account_id`. A client cannot choose another account ID in production.
- Challenge context is created and stored by Shield. The client cannot create its own nonce.
- A challenge is one-time, expires after the configured TTL, and is bound to job, point, and account.
- The server computes the photo hash from the exact uploaded bytes.
- In production, the canonical note is built from `location_stated` and `purpose`; the client cannot submit an arbitrary note hash.
- Photo uploads are restricted to JPEG and capped by `SHIELD_MAX_PHOTO_BYTES`.
- Evidence verification requires authenticated ownership.
- The server writes `written_at`; client timestamps are retained only as capture metadata.

## Capture contract

Required production fields:

- `job_id` — URL path
- `point_id`
- `nonce` — Shield challenge
- `location_stated`
- `purpose`
- `captured_at`
- original JPEG bytes

Optional evidence signals:

- `lat`, `lng`, `accuracy_m`
- `mock_flag`
- Apple App Attest assertion
- Google Play Integrity token

The server derives:

`photo_sha256 = SHA-256(exact JPEG bytes)`

`note_sha256 = SHA-256(canonical_note(location_stated, purpose))`

`bind_hash = SHA-256(photoHash || noteHash || jobId || pointId || nonce || accountId)`

Platform attestation must bind to this exact `bind_hash`.

## Authentication

Supabase Auth access tokens are verified against:

`https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json`

The implementation validates the JWT signature and standard issuer/audience/expiration/subject claims. Supabase documents this JWKS verification model and recommends a high-quality JWT library rather than implementing JWT cryptography manually.

For production set:

`SHIELD_API_AUTH_MODE=production`

and configure `SUPABASE_URL` (or explicit issuer/JWKS URL) and `SUPABASE_JWT_AUDIENCE`.

## API endpoints

Existing `/shield/...` endpoints remain available as the current integration surface. Health is also exposed at `/shield/v1/health`.

- `POST /shield/jobs/{job_id}/challenge`
- `POST /shield/attest/challenge`
- `POST /shield/attest`
- `POST /shield/jobs/{job_id}/photos`
- `GET /shield/evidence/{evidence_id}/verify`

Section 5 deliberately does not yet invent TradeDeck job-membership authorization. That belongs to Section 13, where Shield is connected to TradeDeck's authoritative job/site participant model.

## Security boundaries

- Never put Supabase secret/service-role credentials in iOS or Android.
- Never trust a client-provided account ID in production.
- Never call location data GPS proof; it remains a signal evaluated by Shield.
- Never replace an original object through an upsert path.
- Never accept a second use of a challenge nonce.
