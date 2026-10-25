# Photo list speed

What `GET /shield/captures` (and the share-code and timestamp lookups that share its code) did, and what changed.

- **Table setup once per database file.** Every request and, in a list, every photo re-ran the `CREATE TABLE IF NOT EXISTS` statements on a new connection. `init_once` (in `local_identity.py`) now does it once per process per file. A database file swapped while the server runs is not set up again; restore is already "stop the service first" (`docs/OPERATIONS.md`).
- **One ticket lookup per list**, not one per photo (`tickets.by_hashes`, in batches of 500). Same answers as `by_hash`; a test compares them.
- **Outside-timestamp coverage stops its walk** where an earlier stamp already covered a record and everything before it. Each daily stamp used to walk the whole chain back to its start. Same result as the plain walk; a randomized test compares them on 25 chains with side branches.
- **Index `captures(account_id, received_at DESC)`**, so the newest-first list reads the newest rows instead of sorting the account's rows. It is created with the tables at startup (idempotent).

Already true, so not changed: the database is in WAL mode (the evidence store sets it on the same file), and `UNIQUE(account_id, record_hash)` already covers lookups by account and record.

**Not measured.** Nothing was timed on the live server; the test counts connections (a fixed handful for 50 photos instead of about two per photo plus the setup statements).
