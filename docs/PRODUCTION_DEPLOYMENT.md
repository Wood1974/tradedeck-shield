# Production deployment

## Server
Build `server/Dockerfile`. The supplied `render.yaml` selects a paid Starter web service because the persistent disk at `/data` cannot attach to a Free service; this incurs Render charges. Do not run multiple API replicas against the SQLite deployment. For horizontal scale, replace the Store adapter with PostgreSQL before increasing replicas.

Standalone mode uses `SHIELD_API_AUTH_MODE=local`, `SHIELD_AUTHZ_MODE=local`, and a private random `SHIELD_LOCAL_JWT_SECRET` of at least 32 bytes. Account records, job grants, evidence metadata, and originals reside on the same persistent disk. Supabase and TradeDeck are not called in this mode. Keep `SHIELD_ATTESTATION_MODE=production` and `SHIELD_PLAY_INTEGRITY_MODE=production` for real device captures. Configure the Apple app ID, Android package/cloud project/service account, and HTTPS API base URLs in both apps. Enable `SHIELD_TIMESTAMP_REQUIRED=true` only after an RFC3161 gateway is configured.

After creating the service and setting secrets, provision the first administrator from the server shell with `cd /app && python -m app.local_identity create-admin --email owner@example.com`. The command prompts for a 12+ character password. An administrator signs in with `POST /shield/auth/login`, creates capturer accounts via `POST /shield/admin/accounts`, and grants each allowed job and point via `POST /shield/admin/job-grants`. Capturers cannot self-register or assign themselves work. `DELETE /shield/admin/job-grants` revokes a job point; `POST /shield/admin/accounts/{account_id}/deactivate` invalidates an account and its tokens. `POST /shield/admin/accounts/{account_id}/reset-password` revokes old tokens; a locked-out administrator can run `python -m app.local_identity reset-password --email owner@example.com` from the server shell. Do not put passwords or access tokens into source files or logs.

## Forgot password (emailed one-time code)
The phone app's **Forgot password?** calls `POST /shield/auth/forgot` and `POST /shield/auth/reset`. A code is emailed through Resend, so the service needs two settings: `RESEND_API_KEY` (a sending-only key) and `SHIELD_MAIL_FROM` (for example `Shield <no-reply@tradedeckapp.com>`). Without them `/forgot` answers 503 `email_not_configured`.

The sender address must be on a domain verified in Resend. Until the domain's DNS records are in place, Resend's test sender `Shield <onboarding@resend.dev>` works only for the Resend account owner's own email address.

A code is 8 digits, lasts 15 minutes, works once and allows 5 tries. Each account gets at most 3 codes an hour. `/forgot` gives the same answer whether or not the email has an account. A successful reset signs the account out everywhere. It does not depend on an administrator, so it still works after `lock-admin`; a locked administrator account still cannot be reset.

## Stored photos

A signed-in phone uploads each sealed photo (the signed record plus the original JPEG) to `POST /shield/captures`. It is stored under `$SHIELD_STORAGE_ROOT/captures/<account>/` (on Render that is `/data/storage`, the same 10 GB disk as the database) and listed with `GET /shield/captures`; `GET /shield/captures/<record_hash>/photo` returns the JPEG. Only the account that uploaded a photo can list or read it, and there is no administrator route to read one.

- Nothing is stored unless the record's bytes reproduce its hash, the whole uploaded file hashes to the signed `photo_sha256`, and the device signature verifies. Failing uploads are refused with a reason; the phone keeps its copy. Uploading the same record twice is safe.
- The Apple assertion, when the phone sends one, is checked against the key the account enrolled and the result is stored as `attest` (`verified`, or the reason it could not be). A missing or failed assertion never blocks a photo. Assertions are checked in the order they were made (Apple's counter must rise), so the app uploads oldest first.
- Limits: `SHIELD_MAX_PHOTO_BYTES` (15 MiB) per photo and `SHIELD_ACCOUNT_QUOTA_MB` (1024) per account. The disk is shared, so size the quota to the number of accounts, and **back up `/data`**: photos live only there and on the phones.
- What this does not show: who holds the signing key (it is not tied to the account), that the scene is true, or the time beyond the phone's clock.
- This changes what the app tells people: photos are no longer only on the phone. Update the privacy policy and any "stays on this phone" wording before a public release.

## iOS
Open `ios/ShieldCamera/ShieldCamera.xcodeproj`, set the production bundle/team and HTTPS API URL, and archive with the owner's distribution certificate and provisioning profile. The Debug configuration uses the development App Attest entitlement; Release uses `ShieldCameraProduction.entitlements` with the production environment. Match `SHIELD_APP_ID` to the signing team's ID and bundle identifier. The app signs into Shield and keeps the access token in memory for that session. No gallery entitlement or picker is used. Validate the Swift build and a physical-device production assertion before release.

## Android
Set the production application ID/signing config, `SHIELD_CLOUD_PROJECT_NUMBER`, production API base URL, Play Integrity linkage, release keystore, and build an AAB. The repository does not contain a signing key; keep it and its passwords outside Git. Publish through Play Console internal testing before production. Validate the Kotlin build, login, grant denial, challenge, Play token, and seal on a Play-distributed device.

## Operational gates
Before public release: verify Apple App Attest on physical production-signed devices; verify Play Integrity from Play-distributed builds; run the complete test suite in CI; configure backups for `/data`; exercise restore; configure alerting; test nonce replay, authz denial, oversized uploads, corrupted originals, custody-chain tampering, voids, and independent verification.
