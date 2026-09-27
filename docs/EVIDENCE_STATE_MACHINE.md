# TradeDeck Shield — Section 6: Evidence State Machine

The evidence lifecycle is server-enforced. Client UI must not be treated as an authority for evidence state.

## States

- `challenge_issued` — server has issued a one-time capture challenge.
- `capture_received` — original photo and required evidence inputs reached Shield.
- `verified` — hashes, challenge context, configured platform attestation, and validation rules passed.
- `sealed` — immutable evidence record was created and the original was stored.
- `amended` — a later authorized amendment exists; the original sealed evidence is not rewritten.
- `voided` — evidence is permanently marked void and is never deleted as if it did not exist.
- `rejected` — capture failed validation and cannot proceed.

## Legal transitions

```text
challenge_issued -> capture_received -> verified -> sealed
       |                 |                 |
       v                 v                 v
    rejected          rejected           rejected

sealed -> amended -> voided
sealed -> voided
```

There is no transition back to an earlier state. Terminal `rejected` and `voided` states cannot transition again.

## Server behavior

A successful capture records the validated path `capture_received -> verified -> sealed` in `state_events`. The state and its history are server-generated; clients cannot submit an arbitrary final state.

The state endpoint returns the current state and append-only state history to the authenticated evidence owner.

## Section boundary

This section establishes the lifecycle invariant. Full amendment/custody workflows, independent verification, and production database immutability controls are handled by later sections.
