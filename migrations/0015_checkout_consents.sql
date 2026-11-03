-- The tick box before Stripe (owner decision, 3 November 2026): one row per
-- checkout the buyer opened after accepting the Terms, as proof of that
-- consent and of the request for immediate access, and to answer payment
-- disputes and fraud. Additive only: code from before this migration never
-- reads it. Kept 13 months, then deleted by the API's quarter-hourly pass;
-- it outlives account deletion on purpose (Article 17(3)(e)), like
-- trial_claims, so no cascade.
create table checkout_consents (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id),
    product text not null default 'glarion',
    -- e.g. 'studio_yearly'.
    plan text not null,
    terms_version text not null,
    accepted_at timestamptz not null default now(),
    -- The address the request came from (Cloudflare's CF-Connecting-IP).
    ip text,
    -- Coarse only, e.g. 'Firefox on Windows'; never the full browser string.
    user_agent_family text,
    -- Set once Stripe has created the session.
    checkout_session_id text
);

create index checkout_consents_accepted_idx on checkout_consents (accepted_at);
create index checkout_consents_user_idx on checkout_consents (user_id);
