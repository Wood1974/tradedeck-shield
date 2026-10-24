# Checking a photo against the stored copy (share codes)

Someone who needs a photo checked (an inspector, a lender) can compare it with the copy Shield stored, with no account, if the photographer gives them a **share code** and the **original file**.

- The photographer makes a code for one uploaded photo: `POST /shield/captures/<record_hash>/share` (`{"days": 1-90}`, default 30). The code is 26 random characters, shown once, kept only as an HMAC, expires, and can be withdrawn with `DELETE /shield/shares/<id>`. `GET /shield/captures/<record_hash>/shares` lists the photographer's codes (never the codes themselves).
- The checker opens `/check` (or posts to `POST /shield/v1/compare` with `code` and `photo`). The link may carry the code in its `#fragment`, which no server ever receives.
- **Private to the photographer:** a wrong, expired or withdrawn code, and a file with no code, all answer the same `404 not_found`. Nothing is revealed without a code. The file is read in memory and dropped.
- **The answer is facts only:** matched or not; the upload time on Shield's clock; whether the stored photo is unchanged and the record's device signature verifies; the Apple device-check result as stored; and, about the uploader, only whether the account passed the photo-ID and selfie check and on what day (`passed`, `test_mode` or `not_verified`). No name, account id, location, note or image.
- Each check is appended to a hash-chained log (`compare_log`, the older custody-chain code): share id, result and time only. No file, no address.
- **Limits:** only uploaded photos can be compared. A copy sent by email or a messaging app is usually recompressed and will not match, so the checker page and every no-match answer say to use the original file, sent as a file or attachment. A match does not show the scene is true, who held the signing key (it is not tied to the account), or when the photo was taken. A global cap of 600 checks an hour guards against floods; the per-address limiter may see only Render's proxy address (not checked).
- Merkle proofs over uploaded records are planned as a second stage; they are not built.

A stored photo can be checked by an outsider only with a share code the photographer made (private to the photographer). The checker learns only whether the uploader's account passed the ID check, never a name. Only uploaded photos can be compared, and only the original file matches.
