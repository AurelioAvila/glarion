-- Anonymous operation counts, not visitor records or a user-level funnel.
create table growth_counts (
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
