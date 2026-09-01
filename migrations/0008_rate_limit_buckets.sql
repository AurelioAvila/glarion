create table rate_limit_buckets (
    scope text not null,
    client_key text not null,
    window_started_at timestamptz not null default now(),
    attempt_count bigint not null default 1 check (attempt_count > 0),
    primary key (scope, client_key)
);

create index rate_limit_buckets_expiry_idx on rate_limit_buckets (window_started_at);
