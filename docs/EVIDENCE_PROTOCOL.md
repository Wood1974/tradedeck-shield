# TradeDeck Shield — Evidence Core Protocol v1

This document locks the evidence-core contract. Later components — API,
storage, native camera, attestation, and TradeDeck — must implement this
contract rather than redefine it.

## Capture identity

Every capture is bound to:

- signed-in `account_id`
- `job_id`
- `point_id`
- server-issued `nonce`

The challenge TTL is **120 seconds**. A retake is a new capture: new nonce,
new photograph, and new note.

## Photograph

The photograph hash is SHA-256 over the **exact original photo bytes** captured
by the native camera and subsequently received by the server.

```text
photo_sha256 = SHA-256(photo_bytes)
```

The original bytes are the evidence object. Derived/compressed representations
must not replace the original.

## Capture note

The note is created in the **same session as the shutter**. It is not a later
caption.

The v1 note has exactly two required human fields:

- `location_stated` — where the signer states the capture was made
- `purpose` — what the capture documents / why it is being taken

Both are trimmed at the edges, then encoded as canonical UTF-8 JSON:

```json
{"location_stated":"...","purpose":"..."}
```

No spaces are added by the canonical serializer. Unicode is preserved.

```text
note_sha256 = SHA-256(canonical_note_utf8)
```

Missing location or purpose means the point is **incomplete**. The system must
never invent a note.

## Bind hash

The locked v1 bind formula is:

```text
bind_hash = SHA-256(
  photo_sha256 ||
  note_sha256 ||
  job_id ||
  point_id ||
  nonce ||
  account_id
)
```

`||` means direct UTF-8 concatenation. There are **no separators and no length
prefixes**.

This exact encoding is part of the protocol and has a test vector in
`server/tests/test_protocol.py`.

## Server authority

The client may calculate hashes for immediate feedback, but the server must
recalculate the photograph and note hashes from the received bytes and rebuild
the bind hash from server-authoritative identity/challenge values.

`written_at` is always server-written time. It is not accepted from the client
as the authoritative save time.

## Location language

The protocol has exactly three location verdicts:

- `consistent`
- `flag`
- `reject`

Location is an evidence/risk signal. Shield must never describe it as
**GPS-verified**.

## Session rules

- No gallery/file-picker path for a Shield evidence point.
- Leaving/interruption of the camera capture invalidates that in-progress
  capture session; the point remains open.
- A retake creates a new nonce, photo, and note.
- An amendment to a note does not alter the original photo hash; it is a new
  custody/amendment record.
- Original evidence bytes are never silently replaced.

## Platform attestation hook

App Attest / Play Integrity will bind to the capture's protocol material.
Those platform mechanisms are **not part of the hash formula above** and must
not redefine it.

## Non-goals

This protocol does not claim that location proves where a photograph was taken,
that a photograph depicts the claimed subject, or that code/workmanship is
certified. Those are separate evidence or human-review concerns.
