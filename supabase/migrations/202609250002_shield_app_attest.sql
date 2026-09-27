create table if not exists public.shield_app_attest_keys (
  key_id text primary key,
  account_id uuid not null,
  public_key_der_b64 text not null,
  environment text not null check (environment in ('development','production')),
  counter bigint not null default 0,
  receipt_b64 text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.shield_app_attest_challenges (
  nonce text primary key,
  account_id uuid not null,
  expires_at timestamptz not null,
  used_at timestamptz
);

alter table public.shield_app_attest_keys enable row level security;
alter table public.shield_app_attest_challenges enable row level security;

create policy "shield app attest key owner read"
on public.shield_app_attest_keys for select to authenticated
using ((select auth.uid()) = account_id);

-- Challenges and key registration are server-authoritative. Native clients never write
-- these tables directly; privileged backend code performs inserts/updates after verification.
