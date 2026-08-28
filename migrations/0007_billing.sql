-- Subscriptions.

alter table entitlements add column stripe_customer_id text;
alter table entitlements add column stripe_subscription_id text;
alter table entitlements add column subscription_status text;
-- When the paid period ends. Kept so the account can be shown its own
-- renewal date without a round trip to Stripe on every page load.
alter table entitlements add column current_period_end timestamptz;

create unique index entitlements_stripe_customer_idx
    on entitlements (stripe_customer_id)
    where stripe_customer_id is not null;

-- Webhooks arrive more than once. Stripe retries on any non-2xx, and will
-- redeliver after a timeout even when we did process the event, so every
-- handler has to be safe to run twice.
--
-- Claiming the id before doing the work makes that structural rather than
-- something each handler has to remember: a second copy of an event finds
-- the row already there and stops.
create table stripe_events (
    id text primary key,
    event_type text not null,
    received_at timestamptz not null default now(),
    -- Null until the work finished. A row claimed but never completed is a
    -- handler that crashed partway, which is worth being able to find.
    completed_at timestamptz
);

create index stripe_events_incomplete_idx on stripe_events (received_at)
    where completed_at is null;
