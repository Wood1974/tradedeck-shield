# Section 7 — Supabase Storage & Custody

Section 7 adds the production persistence boundary for Shield evidence.

## Production model

- Supabase Postgres stores the evidence record and custody events.
- The `shield-photos` Storage bucket is private.
- Originals are write-once by application contract: a sealed original is never overwritten.
- The original SHA-256 is calculated from the exact bytes received by Shield before processing.
- Evidence records are readable only by the authenticated owner through RLS.
- Custody events are append-only from the application contract; no client INSERT/UPDATE/DELETE permissions are granted.
- Amendments and voids are events/state changes; they do not mutate the sealed original.

## Database objects

Migration: `supabase/migrations/shield_evidence_custody_v1.sql`

Tables:
- `public.shield_evidence_records`
- `public.shield_evidence_custody_events`

Storage:
- private bucket `shield-photos`
- JPEG-only
- 15 MiB object limit

## Important deployment boundary

The checked-in FastAPI service continues to use its development Store until Section 5/7 runtime wiring is configured with Supabase credentials. The migration has been applied to the connected TradeDeck Supabase project, but this package does not pretend that a local service is already using the remote database.

## Integrity rule

A successful verification must re-read the original object and compare its SHA-256 to the sealed `photo_sha256`. A mismatch is an integrity failure, not a repaired record.
