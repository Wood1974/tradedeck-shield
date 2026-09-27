# TradeDeck Shield — Complete deployable source package

For current validation and remaining deployment gates, read `docs/HANDOFF_STATUS.md` first.

This package carries the Shield evidence system through Sections 1–22 at source/deployment-package level.

Core protocol: native camera only; exact original JPEG hashing; required human attestation sheet; server nonce; Apple App Attest / Google Play Integrity; server-side job authorization; server sealing; append-only custody/state history; location as `consistent / flag / reject` signal only; independent verification; optional RFC3161 timestamp gateway; evidence viewer; operations/admin controls; CI and deployment manifests.

Standalone mode has Shield-owned accounts and explicit job/point grants in the local persistent database. Supabase and the TradeDeck API are not needed for this mode. The original integration code remains available but is not enabled by the standalone `render.yaml`.

## Run locally
```bash
cd server
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Production
Use `server/Dockerfile` / `render.yaml` and follow `docs/PRODUCTION_DEPLOYMENT.md` and `docs/RELEASE_CHECKLIST.md`. Production credentials, Apple/Google signing identities, store accounts, and optional TSA credentials are intentionally not embedded. The standalone configuration does not require a TradeDeck authorization endpoint.

## Sections
1 Evidence Core; 2 Native Camera; 3 Apple App Attest; 4 Play Integrity; 5 Shield API; 6 State Machine; 7 Storage & Custody; 8 Location Intelligence; 9 Required Attestation Sheet; 10 Independent Verification; 11 hash-chained custody; 12 offline/recovery policy; 13 TradeDeck server authorization seam; 14 capture packs; 15 security hardening; 16 trusted timestamp gateway; 17 verifier UI; 18 operations/admin; 19 identity/permissions; 20 automated CI/tests; 21 production deployment/release checklist; 22 product UI baseline.

Important: source completion is not the same as App Store/Play production approval. Physical-device attestation, native build verification, production signing, secrets, backups, and store submission remain release operations requiring the owner's accounts and credentials. The optional external timestamp gateway remains separate.
