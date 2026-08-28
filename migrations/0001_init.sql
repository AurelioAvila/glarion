-- Initial schema. Ownership verification is modeled as its own table with a
-- hard expiry, not a boolean flag on `targets` — a domain can change owners,
-- so "verified once" must not mean "verified forever".

create extension if not exists pgcrypto;

create table users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    password_hash text not null,
    token_version integer not null default 0,
    created_at timestamptz not null default now()
);

create table targets (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    domain text not null,
    created_at timestamptz not null default now(),
    unique (user_id, domain)
);

-- One row per verification attempt/cycle for a target. `verified_at` is null
-- until a check succeeds; `expires_at` is set only once verified. Scans must
-- join against this table and require verified_at is not null and
-- expires_at > now() — never trust a cached boolean on `targets`.
create table target_verifications (
    id uuid primary key default gen_random_uuid(),
    target_id uuid not null references targets(id) on delete cascade,
    method text not null check (method in ('dns_txt', 'well_known_file')),
    token text not null,
    verified_at timestamptz,
    expires_at timestamptz,
    created_at timestamptz not null default now()
);

create index target_verifications_target_id_idx on target_verifications(target_id);

-- Immutable audit trail of who authorized what scan and when. Never updated,
-- only inserted into — this is the record that matters if a scan is ever
-- disputed by a target owner or a hosting provider.
create table scan_authorizations (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id),
    target_id uuid not null references targets(id),
    target_verification_id uuid not null references target_verifications(id),
    accepted_terms_at timestamptz not null default now(),
    ip_address inet,
    user_agent text
);

create table scan_jobs (
    id uuid primary key default gen_random_uuid(),
    target_id uuid not null references targets(id) on delete cascade,
    scan_authorization_id uuid not null references scan_authorizations(id),
    status text not null default 'queued' check (status in ('queued', 'running', 'completed', 'failed')),
    tool text not null,
    created_at timestamptz not null default now(),
    started_at timestamptz,
    completed_at timestamptz
);

create index scan_jobs_status_idx on scan_jobs(status);

create table scan_results (
    id uuid primary key default gen_random_uuid(),
    scan_job_id uuid not null references scan_jobs(id) on delete cascade,
    severity text not null check (severity in ('info', 'low', 'medium', 'high', 'critical')),
    title text not null,
    description text,
    raw_output jsonb not null,
    created_at timestamptz not null default now()
);

create index scan_results_scan_job_id_idx on scan_results(scan_job_id);

create table entitlements (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    product text not null default 'glarion',
    plan text not null default 'free',
    max_targets integer not null default 1,
    expires_at timestamptz,
    created_at timestamptz not null default now(),
    unique (user_id, product)
);
