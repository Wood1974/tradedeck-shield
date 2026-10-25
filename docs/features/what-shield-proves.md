# What Shield shows, and what it does not

A plain statement of what a Shield photo, a share-code check and an exported file do and do not establish. It is written from what the code checks today, not from what is planned. Marketing copy is the owner's call and is not here; if copy ever claims more than this page, the copy is wrong.

## What a stored photo shows

- **The file is the one that was signed.** The phone signs a record containing the SHA-256 of the original file. The server recomputes the hash from the bytes it received and refuses the upload if they differ. A recompressed copy (email, a messaging app, a screenshot) never matches.
- **Nothing signed has changed since.** Each record carries the hash of the one before it on that phone, so editing, removing or reordering a signed record is detectable. Format: `docs/RECORD_SPEC.md`.
- **Which key signed it.** The record verifies under one device key. The key is not tied to the account: "uploaded by" (the account) and "signed by" (the key) are different facts.
- **It was taken with the native camera.** The app has no gallery, file picker or web camera path; the record says `native-camera`. That is the app's own statement, signed by its own key.
- **When the server received it.** The server's clock at upload. This is the only time the server itself vouches for.

## What the extra checks add, and their limits

| Check | What it shows | What it does not |
|---|---|---|
| Apple device check (App Attest) | Apple vouched for a key on a genuine device running this app, and that key signed this record's hash. Shown only when the server verified Apple's assertion. | Not that the scene is true. Not who holds the phone. A phone that was never enrolled shows "none". A withdrawn phone key reports `attestation_key_revoked`. |
| Clock check | The phone's own clocks (wall clock, monotonic clock, GPS time, boot count) agree with each other and with the ticket. | Not a timestamp. "Consistent" does not show when the photo was taken. |
| Server ticket | A chain began after the server signed a start-of-job ticket, so the chain is anchored no earlier than the ticket. | Not when each photo was taken. Only on photos that started from a ticket. |
| Outside time-stamp (RFC 3161) | The photo's record existed by the time-stamp authority's time. | Not when it was taken. Off on the live server until its time-stamp service is switched on. |
| ID check (Stripe Identity) | The photographer passed a photo-ID and live-selfie check at sign-on, and signed a note with their device key. | Not that the person in the field is the one who passed. A test-mode check is labelled as such and never counted as confirmed. |

## What a share code lets someone see

Only a person holding the code and the original file. They learn whether the file matches the stored copy, when it was uploaded, whether the photographer passed the ID check, and (for codes made after timing was added) the clock-check label and whether an outside time-stamp covers the photo. They do not see the name, email, location, other photos, the notes behind the clock check, or the job. The code works for one photo, stops on its date, and can be withdrawn.

## What the offline checkers show

`verifier/shield_verify.py` checks uploaded records and `verifier/shield_vault_verify.py` checks the app's exports, with no network and no Shield code. Passing means nothing signed changed, the photo is the signed one, the records link and (for a close-out packet) the counts and times are consistent. They say `NOT CHECKED` for what they cannot check (the photographer's note and ID receipt, the Apple token) and never report a pass for it.

## What Shield does not show, in any case

- **That the scene is true or honest.** A real photo of a staged scene is a real photo.
- **Who was holding the phone.** Not the person, not their intent.
- **When a photo was taken, to better than the phone's clock.** The clock check and time-stamp bound the time; they do not set it.
- **Where it was taken, beyond the location the phone reported.** Location is the phone's own report and can be flagged as simulated; it is not independently verified.
- **That a file was never copied.** Shield shows a file is unchanged, not that it is unique.
- **Anything about a photo that was never sealed or uploaded.**
- **Compliance with a building code.** The Build tab lists code references (Utah, IRC) as prompts for what to photograph. A sealed photo of a checkpoint is evidence of what was photographed, not an inspection or a pass.

## Where each statement is enforced

Record format and canonical bytes: `docs/RECORD_SPEC.md`, `server/app/captures.py`. Share replies and their limitation text: `server/app/shares.py` (`LIMITATIONS`, `TIMING_LIMITATIONS`), shown on the check page. Exports: `docs/features/vault-verifier.md`. Enrolled phones: `docs/features/enrolled-phones.md`. If a statement here stops being true, change this page in the same pull request as the code.
