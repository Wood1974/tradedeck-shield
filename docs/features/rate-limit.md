# Rate limit and login throttle

Two separate limits, both held in the server's memory (one instance; a restart or deploy empties them).

- **Per caller, per minute** (`SHIELD_RATE_LIMIT_PER_MINUTE`, 30 on Render, 120 otherwise). Answers `429 rate_limit_exceeded` with CORS headers and `Retry-After: 60`.
- **Per account, wrong passwords** (`SHIELD_LOGIN_MAX_FAILURES`, default 5 inside 15 minutes). The sixth sign-in for that email answers `429 too_many_login_attempts` with `Retry-After: 900`, even with the right password, until the oldest failure is 15 minutes old. A correct sign-in before the limit clears the count. An email with no account is counted the same way, so the answer never says which emails exist. Tradeoff: someone who knows an email can lock that account out for 15 minutes by guessing wrongly; there is no way to tell them apart from the real owner.

## Who counts as one caller
Behind a proxy the server sees the proxy's address, so without help every caller shares one bucket (and one phone syncing many photos can use up everyone's limit).

`SHIELD_TRUSTED_PROXY_HOPS` is the number of proxies in front of the app that each add the address they saw to `X-Forwarded-For`. With N set, the caller is the Nth entry from the right; entries to its left are whatever the caller claimed and are ignored. **Unset or 0 (the default) keeps the old behaviour and never reads the header**, so a header cannot be used to dodge the limit until the owner has said how many proxies there are.

- **Owner step:** the right N for Render has to be confirmed (Render's request logs show the real client address as `clientIP`; compare it with the entries in `X-Forwarded-For` the app receives), then set on the Render service, which redeploys. Setting a number that is too high falls back to the socket address; too low trusts an entry the caller can choose.
- **Not verified:** what address the live server sees today, and how many proxies Render puts in front of it. The Render logs show no 429s since 18 Oct.
