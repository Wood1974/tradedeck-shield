create table if not exists public.shield_evidence_records (
  id uuid primary key default gen_random_uuid(), protocol text not null default 'shield-evidence-v1',
  job_id uuid not null, point_id uuid not null, account_id uuid not null references auth.users(id),
  nonce text not null unique, photo_sha256 text not null, note_sha256 text not null, bind_hash text not null,
  captured_at timestamptz not null, written_at timestamptz not null default now(),
  original_storage_path text not null unique, original_size_bytes bigint not null,
  mime_type text not null default 'image/jpeg', location_json jsonb not null default '{}'::jsonb,
  attestation_json jsonb not null default '{}'::jsonb,
  state text not null check (state in ('capture_received','verified','sealed','amended','voided','rejected')),
  created_at timestamptz not null default now(), sealed_at timestamptz,
  check (original_size_bytes > 0)
);
create index if not exists shield_evidence_records_account_idx on public.shield_evidence_records(account_id);
create index if not exists shield_evidence_records_job_point_idx on public.shield_evidence_records(job_id, point_id);
alter table public.shield_evidence_records enable row level security;
revoke all on public.shield_evidence_records from anon;
grant select on public.shield_evidence_records to authenticated;
drop policy if exists shield_evidence_select_own on public.shield_evidence_records;
create policy shield_evidence_select_own on public.shield_evidence_records for select to authenticated using ((select auth.uid()) = account_id);

create table if not exists public.shield_evidence_custody_events (
  id bigint generated always as identity primary key, evidence_id uuid not null references public.shield_evidence_records(id),
  event_type text not null, actor_id uuid references auth.users(id), actor_type text not null default 'system',
  event_at timestamptz not null default now(), details jsonb not null default '{}'::jsonb, event_hash text
);
create index if not exists shield_evidence_custody_events_evidence_idx on public.shield_evidence_custody_events(evidence_id,id);
alter table public.shield_evidence_custody_events enable row level security;
revoke all on public.shield_evidence_custody_events from anon;
grant select on public.shield_evidence_custody_events to authenticated;
drop policy if exists shield_custody_select_own on public.shield_evidence_custody_events;
create policy shield_custody_select_own on public.shield_evidence_custody_events for select to authenticated using (exists (select 1 from public.shield_evidence_records e where e.id=evidence_id and e.account_id=(select auth.uid())));

insert into storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
values ('shield-photos','shield-photos',false,15728640,array['image/jpeg','image/jpg'])
on conflict (id) do update set public=false,file_size_limit=15728640,allowed_mime_types=array['image/jpeg','image/jpg'];
