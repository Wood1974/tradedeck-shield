# Password hashing

Passwords are hashed with scrypt and a random 16-byte salt. The setting used is stored beside each hash (`local_accounts.password_kdf`), so old hashes keep verifying while new ones are stronger.

| Name | scrypt | Memory | Time here | Used by |
|---|---|---|---|---|
| `scrypt-14-8-1` | N=2^14, r=8, p=1 | 16 MiB | about 40 ms | every account made before the upgrade (column is NULL) |
| `scrypt-15-8-3` | N=2^15, r=8, p=3 | 32 MiB | about 190 ms | new accounts, resets, and upgraded accounts |

`scrypt-15-8-3` is one of the settings OWASP lists as equal in strength to N=2^17, r=8, p=1 (128 MiB). It was chosen for its memory: each sign-in holds it while it runs, and the server has 512 MB, so 128 MiB per sign-in would let a burst of sign-ins use it all. Times were measured on a development machine, not on Render.

- **Upgrade on sign-in.** The first successful sign-in on a legacy account rewrites the hash at the current setting (same password, same salt) if the stored hash is still the one just checked; a password reset that lands in between is never overwritten. It does not bump `auth_version`, so tokens already issued keep working.
- **Same work every attempt.** Every sign-in attempt, for a known account or not, computes one hash at each setting (one verifies, the other is thrown away or is the upgrade), so the time does not say whether an email has an account or which setting it has.
- **Cost.** A sign-in takes about 230 ms instead of 40 ms of CPU. The per-address rate limit and the per-account throttle (`docs/features/rate-limit.md`) bound how many can run at once.
- **Not changed:** password length rules (12 to 1024 characters), the reset-code flow, token lifetime.
- **Not verified:** timing and memory on the live server. Accounts that never sign in again stay on the legacy setting.
