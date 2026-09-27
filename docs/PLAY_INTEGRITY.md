# Section 4 — Google Play Integrity

TradeDeck Shield uses the Play Integrity **Standard API** for Android capture requests.
Google recommends binding the integrity request to the protected user action with
`requestHash`; Shield uses the canonical capture `bind_hash` as that request hash.
The returned encrypted token is sent to the Shield server. The server asks Google
to decode it and validates the returned request package, request hash, timestamp,
application recognition, and device integrity. Google documents this server-side
verification flow and the `PLAY_RECOGNIZED` / `MEETS_DEVICE_INTEGRITY` verdicts.

## Android flow

1. Prepare `StandardIntegrityTokenProvider` with the Google Cloud project number.
2. Build the canonical Shield capture bind hash.
3. Request a Standard Integrity token with `setRequestHash(bind_hash)`.
4. Send the encrypted token with the capture.
5. Server sends it to Google's `decodeIntegrityToken` endpoint.
6. Server checks `requestPackageName` and `requestHash`.
7. Server checks token age and configured app/device/license verdicts.
8. In production, a required Play Integrity failure prevents sealing.

## Production configuration

`SHIELD_PLAY_INTEGRITY_MODE=production`

`SHIELD_PLAY_PACKAGE_NAME=com.tradedeck.shield`

`GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON` or
`GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE` must be configured on the server.
The service account needs the Play Integrity API scope/permission required to
call Google's decode endpoint. Never ship the service-account credential in the
Android app.

Android build configuration must provide `SHIELD_CLOUD_PROJECT_NUMBER` through
Gradle/project configuration. It is not a secret.

## Verdict policy

Default production policy:

- `appRecognitionVerdict == PLAY_RECOGNIZED`
- `MEETS_DEVICE_INTEGRITY` is required
- `MEETS_STRONG_INTEGRITY` is optional and configurable
- `LICENSED` is optional and configurable
- stale/future tokens are rejected
- package mismatch is rejected
- request-hash mismatch is rejected

An Android device does not become “GPS verified” from Play Integrity. Device
integrity and location evidence remain separate signals.

## Replay protection

The Shield capture nonce remains one-time. The Play token is additionally bound
to the exact capture `bind_hash`, and the server checks the token timestamp. A
reused capture challenge cannot produce another sealed evidence record.
