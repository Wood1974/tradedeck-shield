# Handoff status — updated October 20, 2026

(First written September 27, 2026 when this was only a source package. Corrected October 20 to match what is running.)

Shield is live as its own FastAPI service, `tradedeck-shield` on Render (`https://tradedeck-shield.onrender.com`), built from this repo's `main` and redeployed on every merge. It is separate from the `Tradedeck-api` marketplace service. The phone app (`shield-app/` in `Wood1974/Tradeneck`) signs in to it. The release gates below still stand; "live" does not mean store-approved or device-verified.

Two things in this repo are older than the app and are kept for reference: the native `ios/ShieldCamera` and `android/` clients (with `.github/workflows/testflight.yml`), which the Capacitor app replaced, and the Supabase-based modes described in `SHIELD_API.md` and `SUPABASE_CUSTODY.md`, which the deployed server does not use.

## Validated in this package

- Pinned the missing `requests` dependency required by `google.auth.transport.requests`.
- Updated the capture test for the required Section 9 attestation sheet and authenticated verification route.
- Corrected the Play Integrity test fixture so an empty device verdict stays empty.
- Allowed a valid Apple App Attest assertion without an Android Play token in production; a supplied invalid Play token is rejected.
- Server suite: 143 passed on Python 3.11 (run October 20, 2026), including backup integrity and restore tests. (55 passed when first written.) The Android and iOS compile jobs in `ci.yml` build the older native clients; neither native build nor Docker deployment was verified in this Linux environment. The iOS Release App Attest entitlement is configured for production; owner signing credentials are still required.

## Gates before deployment

1. ~~Import the Git bundle to a new repository.~~ Done: the repo is `Wood1974/tradedeck-shield` and `ci.yml` runs on it. Keep server CI green before merging.
2. Standalone mode now has Shield-owned local accounts and exact job/point grants. Provision the first administrator on the service, create capturers, and test that a user without a grant is denied. Keep `SHIELD_API_AUTH_MODE=local` and `SHIELD_AUTHZ_MODE=local`; never use development mode in production.
3. Configure Render secrets marked `sync: false` in `render.yaml`, physical-device Apple and Play credentials, and production API base URLs. Test that iOS and Android each pass their own attestation path. The mobile source was wired for local sign-in, but native compilation and real-device testing were unavailable here.
   The Blueprint explicitly selects the paid Starter plan because persistent disks cannot attach to a Free web service. Review the resulting charges before applying it.
4. In standalone mode the server uses SQLite and files on its persistent disk; the bundled Supabase migrations are historical alternatives and are not used or applied. Back up and restore the database and originals together. Do not apply the package's two differing Supabase evidence schemas to the TradeDeck project.
5. Run CI, test authorization denial, replay, damaged originals, independent verification, backup and restore, and only then enable a public rollout.

An offline backup/restore tool and tests are included. This is not proof of a Render disk restore; the live disk and offsite copy still need a restore drill.

The disk-backed SQLite service is single-instance. Set up backup and restore before collecting real evidence.
