# Section 3 — Apple App Attest

TradeDeck Shield Section 3 moves Apple platform integrity from a placeholder to a server-verified trust path.

## What is implemented

### Registration / attestation
1. Native app requests a one-time server challenge: `POST /shield/attest/challenge`.
2. `DCAppAttestService` creates or reuses a device-bound key stored in Keychain.
3. The app hashes the server challenge and calls `attestKey`.
4. The app sends the CBOR attestation object, key ID, and challenge to `POST /shield/attest`.
5. Server validates the Apple App Attest certificate chain against the pinned Apple App Attestation Root CA.
6. Server validates the App Attest nonce, public-key/key-ID binding, App ID hash, counter, AAGUID, and credential ID.
7. Only a successfully validated key is stored for later assertions.

### Capture assertions
For each evidence capture, the signed client data is the canonical UTF-8 bind-hash string. The app passes `SHA-256(clientData)` to `generateAssertion`. The server independently rebuilds the bind hash from the photo, note, job, point, nonce, and account, then verifies the assertion signature over `authenticatorData || clientDataHash`.

The server also checks:
- stored App Attest public key
- App ID hash
- strictly increasing assertion counter
- account-to-key binding
- optional `apple_bundle_version` and `apple_validation_category` enforcement

A production deployment rejects captures without a trusted App Attest assertion.

## Trust boundary

The native app is never trusted to decide whether its own attestation is valid. The server is authoritative. This follows Apple's App Attest architecture: Apple certifies the device-bound key, while the server verifies the attestation and subsequent assertions. citeturn1search0turn1search4

## Storage

The server stores the verified public key, environment, assertion counter, and receipt reference. The private App Attest key remains managed by Apple's `DCAppAttestService` and is persisted only by its key identifier in the app Keychain.

## Development vs production

The Xcode entitlement is currently `development` so the package can be tested in App Attest's development environment. Production builds must use the production App Attest environment and a registered Apple App ID/team configuration. Apple documents that development keys do not work in production, and distributed builds use the production environment. citeturn0search7

Set:
- `SHIELD_ATTESTATION_MODE=production`
- `SHIELD_APP_ID=<10-digit Team ID>.<bundle identifier>`
- `SHIELD_IOS_BUNDLE_VERSION=<CFBundleVersion>`
- optionally `SHIELD_IOS_VALIDATION_CATEGORY=<expected Apple validation category>`

Do not put Apple private keys or server secrets in the native app.

## Important limitation

This environment cannot run a signed physical iOS build or obtain a live Apple attestation object, so the Apple certificate-chain path was implemented and unit-tested structurally, but a real-device App Attest acceptance test remains required before production release.
