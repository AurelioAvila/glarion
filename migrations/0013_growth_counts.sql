-- Anonymous operation counts, not visitor records or a user-level funnel.
--
-- Renumbered from 0011. Production recorded version 11 with a checksum that
-- no file in this repository reproduces, so every boot after 2026-09-17
-- refused to migrate and the service would not start. The table itself was
-- correct, so this replays the same DDL idempotently under a fresh version
-- rather than rewriting a checksum in a database nobody can reach from CI.
create table if not exists growth_counts (
    day date not null default (now() at time zone 'UTC')::date,
    source text not null check (source in ('direct', 'youtube', 'dev', 'search', 'referral')),
    event text not null check (event in (
        'landing_view', 'sample_report_view', 'signup_view',
        'preview_started', 'preview_completed', 'preview_rejected', 'preview_failed',
        'signup_created', 'domain_verified'
    )),
    total bigint not null default 1 check (total > 0),
    primary key (day, source, event)
);
