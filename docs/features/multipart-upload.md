# Multipart photo upload

`POST /shield/captures/upload` stores a photo like `POST /shield/captures`, with the photo as raw bytes instead of base64 text, so it is a third smaller on the wire and is not held twice in memory while it is decoded.

- Form field `meta`: the same JSON as the older route without `photo_b64` (`record`, `signature_der_b64`, `public_key_uncompressed_b64`, optional `app_attest_key_id`, `app_attest_assertion_b64`). At most 64 KB.
- File field `photo`: the original JPEG bytes. Read with a cap of `SHIELD_MAX_PHOTO_BYTES`; larger is `413 photo_too_large` and nothing is stored.
- Every check after that is the same code (`captures.ingest`): record hash, photo hash, device signature, quota, Apple check, clock check. Same replies, same refusal codes (an empty file is `photo_invalid`; bad `meta` is `422 record_invalid`).
- The JSON route stays. An app that has not been updated keeps working; the app switches to this route in its own change, and the older route is retired only after the old app versions are gone.

Rate limit and sign-in are as for every other route. Nothing new is stored or shown.
