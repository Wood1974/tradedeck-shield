# Enrolled phones

An account can see the phones it has enrolled with Apple App Attest and withdraw one.

- `GET /shield/devices` → `{ devices: [{ id, environment, enrolled_at, photos, revoked_at }] }`. Only the signed-in account's own phones. `photos` is how many of its stored photos that key signed for. The `id` is Apple's key id (a hash of the public key), not a device name or serial number.
- `POST /shield/devices/revoke` with `{ "id": "<key id>" }` → `{ ok: true }`. Rate limited. 404 for a key that is not this account's, with the same answer as for one that does not exist. POST because the phone app's web view may only send GET and POST across origins.

## What revoking does

- New photos signed with that key are stored as before but the Apple check reports `attestation_key_revoked` instead of `verified`. A photo is never refused because of it.
- The key cannot be enrolled again (`attestation_key_revoked`, 409): a withdrawn phone stays withdrawn. A phone enrols a new key to carry on.
- Photos already stored keep the result recorded when they arrived. Revoking does not rewrite history.

## What it does not do

- It does not log the phone out. Sign-in tokens are separate; "sign out everywhere" is the existing route.
- It does not show which person holds the phone. The signing key on the phone is not tied to the account.

Storage: `attestation_keys.revoked_at` (added to an existing table on startup; empty means active).
