# Forgot password (emailed one-time code)
The phone app's **Forgot password?** calls `POST /shield/auth/forgot` and `POST /shield/auth/reset`. A code is emailed through Resend, so the service needs two settings: `RESEND_API_KEY` (a sending-only key) and `SHIELD_MAIL_FROM` (for example `Shield <no-reply@tradedeckapp.com>`). Without them `/forgot` answers 503 `email_not_configured`.

The sender address must be on a domain verified in Resend. Until the domain's DNS records are in place, Resend's test sender `Shield <onboarding@resend.dev>` works only for the Resend account owner's own email address.

A code is 8 digits, lasts 15 minutes, works once and allows 5 tries. Each account gets at most 3 codes an hour. `/forgot` gives the same answer whether or not the email has an account. A successful reset signs the account out everywhere. It does not depend on an administrator, so it still works after `lock-admin`; a locked administrator account still cannot be reset.
