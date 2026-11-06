# Using Shield files in another build

**The rule (owner, Nov 2026): Shield is standalone. Nothing from the marketplace or any other build is merged into Shield. Other builds may use Shield's files. The copy goes one way, out of Shield; nothing flows back.**

"Shield" here means this server (`server/`), `verifier/`, `eval/`, `docs/`, and the phone app (`shield-app/`).

## What may be copied out
- Source files, tests, public docs and test vectors.
- Public keys (for example a ticket or analysis key's public half) and public identifiers such as the app id.

## What may not be copied out, or into Shield
- Private keys, signing material, API keys, environment values, Stripe or Apple credentials, user accounts and photos. These never leave the Shield server's environment or the owner's accounts.
- Anything from another build into Shield: no marketplace code, logins, data, keys or API calls. If another build needs something changed in Shield, the change is made in Shield first, on its own terms, and then copied out again.

## How a copy stays honest
A copy is a snapshot, so it can fall behind. To make that visible:
1. Put the copied files in their own folder in the other build, with a `SHIELD_COPY.md` next to them that states: the source repository, the Shield commit the files came from, the date, and the list of files.
2. Do not edit the copied files in the other build. A change belongs in Shield first; then copy again and update `SHIELD_COPY.md`.
3. To check for drift, compare the recorded commit with Shield's `main`; `git diff <recorded commit> main -- <files>` lists what changed.

This is a convention, not a tool: nothing checks it automatically yet.

## Where Shield and other code share a home today
These are facts, not a design, and the rule above applies to them from now on:
- The phone app lives in `shield-app/` inside the marketplace repo (`Wood1974/Tradeneck`), with its build workflows. App changes made there are Shield changes. No marketplace code is imported by the app (checked by searching its imports); the app talks only to this server.
- An older web Shield (`shield.js`, a Shield tab) and older Shield code in the marketplace backend (`Tradedeck-api`) are a separate, older path. They are not this Shield and should not be presented as it.
- This server still has an old sign-in mode that uses a Supabase JWT (`server/app/auth.py`, `docs/SUPABASE_CUSTODY.md`). Production runs Shield's own accounts (`SHIELD_API_AUTH_MODE=local`). Retiring the old mode is a separate decision.
