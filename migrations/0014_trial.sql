-- The three-day free trial (TRIAL_ENABLED). Additive only: code from before
-- this migration ignores every column and the table, so rolling the code back
-- never needs this rolled back.

-- Kept from the subscription on every webhook so the dashboard and the
-- reminder can answer without a round trip to Stripe.
alter table entitlements add column trial_ends_at timestamptz;
alter table entitlements add column cancel_at_period_end boolean not null default false;
-- Why the paid plan is not in force: payment_failed, canceled,
-- trial_already_used. Null while it is.
alter table entitlements add column blocked_reason text;
-- 'month' or 'year', from the subscription's price.
alter table entitlements add column billing_interval text;
-- What Stripe will take when the trial ends (its invoice preview: coupon and
-- tax included), in the currency's minor unit.
alter table entitlements add column first_charge_amount bigint;
alter table entitlements add column first_charge_currency text;
-- The trial end the reminder was sent for. A new end date (or a new trial)
-- is a different value, so it is reminded again; the same one never twice.
alter table entitlements add column trial_reminder_for timestamptz;
-- The subscription whose first real payment was confirmed by email, so the
-- confirmation goes out once however many events report it.
alter table entitlements add column activation_mailed_for text;

-- One row per trial ever started, so the same person cannot start another one
-- with a new account, the same mailbox written differently, or the same card.
-- Holds no address and no card number: a SHA-256 of the normalised email and
-- Stripe's own card fingerprint. It outlives account deletion on purpose,
-- like scan_authorizations, so no cascade.
create table trial_claims (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id),
    email_hash text not null,
    card_fingerprint text,
    subscription_id text not null,
    created_at timestamptz not null default now(),
    trial_ends_at timestamptz not null
);

create unique index trial_claims_user_idx on trial_claims (user_id);
create unique index trial_claims_email_idx on trial_claims (email_hash);
create unique index trial_claims_card_idx on trial_claims (card_fingerprint)
    where card_fingerprint is not null;
create unique index trial_claims_subscription_idx on trial_claims (subscription_id);
