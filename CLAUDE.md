# CLAUDE.md — tradedeck-shield (Shield server)

Guidance for Claude Code (or any agent) working in this repo. This is the **standalone Shield server**: the evidence and sign-on service behind the Shield iPhone/Android app. The app itself lives in `Wood1974/Tradeneck` under `shield-app/`. Shield is separate from the TradeDeck marketplace (`Tradedeck-api`); it shares only the `tradedeckapp.com` domain.

Verify against the code before building on a feature: this file was written Oct 2026 and goes stale when things change without an update here.

## Working rules (set by the owner)

Standing instructions from the owner. They apply to every session in this repo, so don't wait to be told again.

- **Fix the root cause, once.** No workarounds or "for now" patches. If the real fix is bigger than asked, say so and propose it.
- **Say what was verified and what wasn't.** Never overstate. If something couldn't be run or checked (a device, a live server, a dashboard), say that plainly.
- **The owner merges.** Open PRs as drafts and leave them. Don't merge, and don't start TestFlight or store builds or change live settings (Render env vars, DNS, Stripe, Apple) without the owner's go.
- **Don't watch PRs.** Opening a PR subscribes the session automatically; unsubscribe right away. Check CI only when asked.
- **Decide before building** anything that changes who can see data, what leaves the phone, or what costs money: ask first, with a recommendation.
- **Never print or repeat a password, key or token.** If one has been exposed (in chat, a screenshot, a log), say so plainly so it gets rotated.
- **Say early which steps only the owner can do** (DNS at GoDaddy, the Render shell, the Apple portal, rolling the Stripe key, merging).
- **Keep status updates short.** Long reports only when asked.

## Shield decisions already made

- Live native camera only: no gallery, file picking or web camera.
- Close-out is solo (one person signs it), not multi-party.
- Administrator access is turned off for good at launch (`lock-admin`). After that, new people join by single-use invite code, made before the lock.
- Photos are stored on the Shield server disk and are readable only by the account that took them. No administrator route reads them.
- Honest labels: never say a photo is "attested" unless a server verified Apple's assertion. Say what was actually checked; a valid signature alone does not show the image matches.
- Construction content uses Utah building codes only.

## What's here

- `server/app/main.py`: FastAPI app and routes. `server/app/local_identity.py`: Shield's own accounts (scrypt passwords, HS256 tokens, admin CLI). `password_reset.py`: emailed one-time code via Resend. `attestation.py`: Apple App Attest checks (attestation and assertion). `identity_api.py`: Stripe Identity ID check and signed receipts. `security.py`: rate limiting. Look in `server/app/` for what exists before assuming a feature is there; open PRs add things.
- `docs/RECORD_SPEC.md` is the written format of a photo record; `verifier/shield_verify.py` checks records from that page alone, without Shield's code (`server/tests/test_verifier.py` keeps it in agreement with the server).
- `docs/PRODUCTION_DEPLOYMENT.md` has a section per feature and the pre-release gates. `docs/OPERATIONS.md` covers running it.
- Data: SQLite at `SHIELD_DATABASE_URL`, files under `SHIELD_STORAGE_ROOT`. On Render both are on the 10 GB persistent disk at `/data`. **There is one copy: back up `/data`.**
- Accounts: `SHIELD_API_AUTH_MODE=local` turns on Shield's own accounts. The app signs in at `/shield/auth/login`.
- `SHIELD_APP_ID` is `<team id>.<bundle id>` (`766456AWH4.app.tradedeck.shield`). A typo there makes every Apple check fail.

## Running it

- Tests: `cd server && python -m pytest` (install `requirements.txt` plus `pytest` and `httpx`). Run them before any push.
- Cloud sessions can't call the live server (the egress proxy refuses it). Check the live server through Render's logs and the dashboard, not `curl`.

## Facts that bite

- **Merging to `main` deploys to production within seconds** on the Render service `tradedeck-shield` (`https://tradedeck-shield.onrender.com`, the only address the app uses). Changing an environment variable redeploys too. The services `tradedeck-shield-1` and `tradedeck-shield-qtt8` are old duplicates the app doesn't use.
- The Cloudflare check "Workers Builds: tradedeck-shield" is unrelated to this repo's code (there is no Worker) and is red on every PR. Ignore it; disconnect it in the Cloudflare dashboard to clear it.
- Email: `tradedeckapp.com` needs its DNS records at GoDaddy verified in Resend before mail can go to anyone. Until then the test sender `onboarding@resend.dev` only reaches the Resend account owner.
- The signing key on the phone is not tied to the account: "uploaded by" (account) and "signed by" (key) are different facts. Don't blur them in the UI or the docs.
