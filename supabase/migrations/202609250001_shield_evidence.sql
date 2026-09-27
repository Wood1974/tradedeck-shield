create extension if not exists pgcrypto;

create table if not exists public.shield_evidence (
  id uuid primary key default gen_random_uuid(),
  job_id text not null,
  point_id text not null,
  account_id uuid not null,
  nonce text not null unique,
  photo_sha256 text not null check (photo_sha256 ~ '^[0-9a-f]{64}$'),
  note_sha256 text not null check (note_sha256 ~ '^[0-9a-f]{64}$'),
  bind_hash text not null check (bind_hash ~ '^[0-9a-f]{64}$'),
  captured_at timestamptz not null,
  written_at timestamptz not null default now(),
  location jsonb not null,
  attestation jsonb not null,
  original_path text not null unique,
  status text not null check (status in ('sealed','incomplete','rejected')),
  created_at timestamptz not null default now()
);

create table if not exists public.shield_custody_events (
  id bigint generated always as identity primary key,
  evidence_id uuid not null references public.shield_evidence(id),
  event_type text not null,
  event_at timestamptz not null default now(),
  details jsonb not null
);

alter table public.shield_evidence enable row level security;
alter table public.shield_custody_events enable row level security;

-- Reads are intentionally limited to the owning account. Server-side custody writes use a
-- privileged backend path; do not expose service-role credentials to the native client.
create policy "shield evidence owner read"
on public.shield_evidence for select to authenticated
using ((select auth.uid()) = account_id);

create policy "shield custody owner read"
on public.shield_custody_events for select to authenticated
using (exists (
  select 1 from public.shield_evidence e
  where e.id = evidence_id and e.account_id = (select auth.uid())
));

-- Private immutable bucket. Uploads are performed by server-issued signed upload URLs or
-- a server-side privileged client; no overwrite policy is granted.
insert into storage.buckets (id, name, public)
values ('shield-photos','shield-photos',false)
on conflict (id) do nothing;
