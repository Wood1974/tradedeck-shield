# Sign-up by invite code

Accounts are no longer made only by an administrator. A person with an invite code makes their own account in the app (a normal capturer account, never an administrator), so people can still join after administrator access is turned off.

- Make codes before launch with `POST /shield/admin/invites` (`{"count": 5, "days": 14}`, administrator token) or in the Render shell: `python -m app.signup mint --count 5 --days 14`. Each code is shown once; only a hash is stored. Codes work once and expire (14 days by default, 90 at most).
- `POST /shield/auth/signup` spends a code. A wrong, used or expired code all answer `invalid_or_expired_invite`. A code is not spent when the account cannot be made (short password, email already in use).
- After `lock-admin` the HTTP route is closed with the rest of `/shield/admin/*`. Codes already made keep working until they expire, and the shell command still works for whoever has the Render shell, so make enough before the lock or keep that access.
- Every account can run the ID check, which costs a Stripe Identity fee each time. Invite-only sign-up is what keeps that bounded. Open sign-up is deliberately not offered.
