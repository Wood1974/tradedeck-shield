# Identity & permissions
Supabase JWT `sub` is the account identity in production. Job/point authorization is independently checked server-to-server. Evidence owner endpoints require the same account ID. Independent verification intentionally exposes only cryptographic verification facts. Admin health requires an explicit server-side allowlist.
