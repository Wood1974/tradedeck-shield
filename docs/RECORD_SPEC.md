# Shield photo record — specification v1

Everything needed to check a Shield photo record without running Shield's code or asking Shield. `verifier/shield_verify.py` is a
separate implementation written from this page; the server's own check lives in `server/app/captures.py`. A test
(`server/tests/test_verifier.py`) makes the two agree on 200 random records and on the frozen vectors in
`server/tests/vectors/capture-record-v1.json`. If this page and a vector ever disagree, the vector wins and this page is wrong.

## 1. The record

A record is a JSON object with the signed fields below plus two links, `prev_hash` and `record_hash`.

| Field | Type | Rule |
|---|---|---|
| `version` | integer | must be `1` |
| `checkpoint_id` | text | 1 to 512 characters |
| `photo_sha256` | text | 64 lowercase hex characters: SHA-256 of the original file |
| `ticket_id` | text | 1 to 512 characters |
| `wall_time_ms` | integer | the phone's clock, milliseconds |
| `monotonic_ms` | integer | not negative; the phone's monotonic clock |
| `flags` | integer | not negative |
| `boot_id` | text, optional | 1 to 512 characters |
| `boot_count` | integer, optional | not negative |
| `gnss_time_ms` | integer, optional | GPS time, milliseconds |
| `location_simulated` | boolean, optional | the phone's own report |
| `sensor_hash`, `depth_hash` | text, optional | 64 lowercase hex |
| `depth_present` | boolean, optional | `depth_hash` present if and only if this is `true` |

Integers are whole numbers with absolute value at most 9007199254740991 (2^53 − 1). Floats and booleans are not integers. Any
field not listed (other than the two links) makes the record invalid, because the signature would not cover it. A field that is
absent and a field that is `null` are the same thing.

## 2. Canonical bytes

Take only the signed fields that are present, build one object, and serialize it with keys sorted, no spaces (`,` and `:`
separators) and every non-ASCII character escaped as `\uXXXX` (for example `café` becomes `café`). Encode as ASCII.

## 3. The two hashes and the signature

```
signing_message = canonical_bytes || "|" || prev_hash          (prev_hash as UTF-8 text, 64 hex characters)
record_hash     = hex( SHA-256(signing_message) )
signature       = ECDSA P-256 over SHA-256, DER encoded, of signing_message
public key      = uncompressed point 0x04 || X || Y, base64
```

`prev_hash` is the `record_hash` of the record before it on the same phone. A phone's first record uses the ticket hash as its
`prev_hash`. A chain is intact when each record's `prev_hash` equals the previous record's `record_hash`.

## 4. What a package looks like

What the phone sends to the server, and what the checker reads:

```
{ "record": { ...signed fields..., "prev_hash": "...", "record_hash": "..." },
  "signature_der_b64": "...", "public_key_uncompressed_b64": "...", "photo_b64": "..." (optional) }
```

## 5. Checks, in order

1. The record has only the fields above, with the right types (section 1).
2. `record_hash` equals the hash in section 3.
3. SHA-256 of the original file equals `photo_sha256`. Only the original file matches: a copy sent by email or messaging is usually
   recompressed and never matches.
4. The signature verifies with the public key supplied.
5. Each record's `prev_hash` equals the record before it.

## 6. What a pass shows, and what it does not

Shows: no signed field changed after it was signed; the file is the one that was signed; the records link in order.

Does not show: who holds the signing key (the key is not tied to a person or account); that the scene is real or was not staged;
the time, beyond what the phone's own clock said (the clock limits in the phone's time labels are a consistency check, not a
timestamp); that Apple's device check passed (that is a separate server-side result); or that a record is the latest one — records
can be left out of a list you are handed unless you hold a chain head from another source.

## 7. Running the checker

```
python verifier/shield_verify.py upload.json --photo original.jpg
```

Exit code 0: every check ran and passed. 2: a check failed. 3: nothing failed, but the signature could not be checked because the
`cryptography` package is not installed. It says so and never reports that case as a pass.
