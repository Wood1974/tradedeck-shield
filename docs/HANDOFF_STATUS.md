# Handoff status — September 30, 2026

This change starts from GitHub branch `fix/authoritative-capture-location` at
`c28465293d0420cc1c6160b63071496a0d75c355`, newer than main and the original bundle.
Its trusted job pins, shutter location snapshots, camera interruption guards and
signed IPA selection are preserved.

## Validated and implemented

- Baseline CI run `36528311417` succeeded on September 29. It validated the baseline
  server and unsigned native builds, not these edits or physical-device capture.
- New server regressions cover custody/hash damage, illegal state history,
  testimony changes/deletion, path traversal/symlink escape, exclusive originals,
  rollback, concurrent replay, amendments, voids, owner-only receipts, iOS-only
  readiness, location rejection and backup/restore of testimony/custody.
- Canonical human testimony is now retained. Migration preserves older evidence;
  old text cannot be recovered from its hash and is explicitly unavailable. New
  evidence fails verification if its retained text is missing or altered.
- Nonce, Apple counter, evidence/state/custody and amendment links commit together.
  Originals are created exclusively and fsynced first. Normal failures remove the
  new file. A process crash can leave an unreferenced original for inspection.
- Both Dockerfiles include the verifier page. CI builds both contexts and tests
  the packaged viewer, strict readiness and authentication.
- The Blueprint selects an iOS-only production launch, paid Starter and a 10 GB
  persistent disk. Disabled Android tokens are rejected; Google credentials are
  unnecessary for iOS-only readiness. No development attestation bypass is used.
- iPhone sealing renews an unused expiring challenge after device registration.
  It checks the original nonce receipt before retrying; an uncertain upload does
  not automatically create a second record.

## Remaining gates, in order

1. Pass updated server, Docker and native CI; review and merge the fixes before
   deploying the Blueprint. Baseline CI does not validate changed code.
2. Confirm the intended Render workspace; configure a single-instance paid service,
   persistent disk, production secrets, HTTPS URL and strict readiness. Deployment
   and production disk restore have not been established by this document.
3. Provision the first admin interactively from the server shell. Create a capturer,
   grant exact job/point access, set the job pin and test denial. Keep passwords
   out of source and logs.
4. Stop writes for consistent database/original backups; copy archives off disk
   to private storage and perform an empty-target production restore drill before
   collecting real evidence.
5. Repair Apple signing prerequisites. TestFlight run `36528039367` failed at the
   credential preflight: `IOS_DISTRIBUTION_CERTIFICATE_BASE64` was unavailable in
   that run. Archive/export/upload were skipped. This is historical evidence,
   not a current secret inventory. Recheck all four secrets, certificate identity,
   matching App Store profile, production App Attest entitlement and ASC access.
6. Upload with a fresh build number; install through TestFlight on a supported
   physical iPhone. Test login, denial, capture, testimony, production App Attest,
   sealing, originals, interruption, expiry and lost-response recovery against
   the deployed server.
7. Repeat denial, concurrent replay, oversized uploads, original/testimony/custody
   corruption, amendment, void and independent-verification tests on production.
   Supply store privacy/disclosure/support information and incident contacts.
8. Enable Android only after credentials, signing and Play-distributed physical
   tests pass. Set `SHIELD_ENABLED_PLATFORMS=ios,android` and recheck readiness.

## Trust and recovery limits

API append-only behavior and chained hashes do not prevent a server administrator
from rewriting files/records and recomputing hashes. Immutable storage or external
anchoring remains necessary before claiming evidence cannot be altered. The
optional timestamp gateway stores its returned token; the independent verifier
does not yet validate its signer or imprint.

Mobile recovery is session-only. There is no durable offline queue or receipt
journal across app termination/background discard. Do not promise complete offline
recovery. SQLite is single-instance; replace the store before scaling replicas.
Historical Supabase schemas are unused in standalone mode and must not be applied
to TradeDeck.
