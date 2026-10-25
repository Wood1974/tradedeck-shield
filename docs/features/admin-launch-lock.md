# Launch: turn administrator access off for good
Administrator access is for setup only. Before launch, create every capturer account and grant its jobs. At launch, run once from the server shell:

`cd /app && python -m app.local_identity lock-admin`

It asks you to type `LOCK`. It then disables every administrator account and revokes their tokens, writes a permanent lock row to the database, and from then on: every `/shield/admin/*` route returns 403, no administrator can sign in, be created, or have a password reset, and `SHIELD_BOOTSTRAP_ADMIN_*` does nothing. Capturer accounts keep working. Deleting `SHIELD_ADMIN_LOCKED` from the environment does not undo it; only the database row counts once written. There is no self sign-up, so no accounts can be added after the lock.

This stops the app, the API and every login from reaching administrator functions. Whoever owns the hosting account can still read the server's disk, so lock that account down separately.
