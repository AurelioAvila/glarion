-- Run privately with psql; no public analytics endpoint. UTC reporting window.
-- These are operation counts, NOT unique users or cohort conversion rates.
begin read only;
select day, source,
    sum(total) filter (where event = 'landing_view') as landing_views,
    sum(total) filter (where event = 'sample_report_view') as sample_views,
    sum(total) filter (where event = 'signup_view') as signup_views,
    sum(total) filter (where event = 'preview_started') as checks_started,
    sum(total) filter (where event = 'preview_completed') as checks_completed,
    sum(total) filter (where event = 'preview_rejected') as invalid_checks,
    sum(total) filter (where event = 'preview_failed') as unreachable_checks,
    sum(total) filter (where event = 'signup_created') as accounts_created,
    sum(total) filter (where event = 'domain_verified') as ownership_verifications
from growth_counts where day >= (now() at time zone 'UTC')::date - 6
group by day, source order by day, source;

-- Authoritative all-source totals; not attributable to a particular campaign.
-- Current-state snapshot: account removal and subscription changes affect it.
select count(*) filter (where created_at >= now() - interval '7 days') as accounts_created_7d,
       count(*) filter (where email_verified_at is not null) as confirmed_accounts_current
from users where email not like 'deleted-%';
select count(distinct target_id) as currently_verified_domains
from target_verifications where verified_at is not null and expires_at > now();
select plan, subscription_status, count(*) as subscriptions_current
from entitlements where product = 'glarion' and plan <> 'free'
group by plan, subscription_status order by plan, subscription_status;
commit;
