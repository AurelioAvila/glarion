//! Halloween 2026: at least 50% off the first month or year of every paid plan,
//! from release until 23:59:59 on 6 November (Europe/Rome). Owner decision
//! of 10 October 2026, the same offer PC Tweaker and Redaxa run.
//!
//! `reference` is the only price that may be struck through. EU law (Omnibus
//! Directive, art. 17-bis Codice del consumo) allows the LOWEST price charged
//! to the public in the 30 days before the reduction starts, and the
//! percentage shown is measured against it. Reconstructed from the live
//! Stripe Prices and every Glarion Checkout Session since August (none was
//! paid, none carried a discount): Studio €39/€350 and Agency €99/€750 since
//! 28–30 August, Solo €19/€170 since 2 September, unchanged since. So the
//! references equal today's prices.
//!
//! Price rule (owner decision, 10 October 2026): a real 50% or more off the
//! lawful reference, rounded down to a round figure: the highest P with
//! P <= 50% of the reference, where P is a whole euro amount or ends in ,99,
//! and from 100 euro a multiple of 5. Badges show the real percentage:
//! Solo 19 -> 9 (52%), 170 -> 85; Studio 39 -> 19 (51%), 350 -> 175;
//! Agency 99 -> 49 (50%), 750 -> 375.
//!
//! Amounts are euro cents excluding VAT, like the Stripe Prices. The coupon
//! behind each offer takes exactly `regular - price` off the first paid
//! invoice once: a Solo trial's zero invoice does not use it up (checked on
//! Stripe test clocks, 10 October 2026). Coupons cannot be edited, so another
//! amount or end date needs new IDs, and no STRIPE_PRICE_* may change during
//! the window. The `halloween_coupons` binary creates and checks them;
//! nothing here talks to Stripe.
//!
//! A once-only coupon on a trial waits for the first paid invoice. Should the
//! billing portal ever allow switching price, a downgrade during the trial
//! (Solo yearly to monthly share a product) could leave a coupon larger than
//! that invoice; today the portal offers no plans to switch to (both live
//! configurations, 10 October 2026).
//!
//! Next promotions: until about 6 December the lowest prices of the previous
//! 30 days are these promo prices, so a Black Friday reduction must strike
//! them, not the list prices.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::billing::{Interval, Plan};

pub const PROMO_ID: &str = "halloween50-2026";
/// The earliest go-live; nothing is discounted until PROMO_ID is set.
pub const STARTS_AT: &str = "2026-10-10T00:00:00Z";
/// Exclusive: the last second on sale is 23:59:59 on 6 November, Rome (CET).
pub const ENDS_AT: &str = "2026-11-06T23:00:00Z";
/// Stripe's shortest Checkout lifetime: a checkout opened in the last minutes
/// stays payable this long, never longer.
pub const GRACE_SECONDS: i64 = 30 * 60;

pub struct Offer {
    pub plan: Plan,
    pub interval: Interval,
    pub regular: i64,
    pub reference: i64,
    pub price: i64,
}

pub const OFFERS: [Offer; 6] = [
    offer(Plan::Solo, Interval::Monthly, 1_900, 1_900, 900),
    offer(Plan::Solo, Interval::Yearly, 17_000, 17_000, 8_500),
    offer(Plan::Studio, Interval::Monthly, 3_900, 3_900, 1_900),
    offer(Plan::Studio, Interval::Yearly, 35_000, 35_000, 17_500),
    offer(Plan::Agency, Interval::Monthly, 9_900, 9_900, 4_900),
    offer(Plan::Agency, Interval::Yearly, 75_000, 75_000, 37_500),
];

const fn offer(plan: Plan, interval: Interval, regular: i64, reference: i64, price: i64) -> Offer {
    Offer {
        plan,
        interval,
        regular,
        reference,
        price,
    }
}

pub fn interval_str(interval: Interval) -> &'static str {
    match interval {
        Interval::Monthly => "monthly",
        Interval::Yearly => "yearly",
    }
}

pub fn coupon_id(plan: Plan, interval: Interval) -> String {
    format!(
        "{PROMO_ID}-glarion-{}-{}",
        plan.as_db_str(),
        interval_str(interval)
    )
}

/// Rounded down, so the badge never claims more than the real discount.
pub fn percent_off(reference: i64, price: i64) -> i64 {
    (reference - price) * 100 / reference
}

fn at(value: &str) -> DateTime<Utc> {
    value.parse().expect("promotion dates are valid RFC 3339")
}

/// Switched on by `PROMO_ID=halloween50-2026` once the coupons are verified;
/// `PROMO_DISABLED=1` or unsetting PROMO_ID stops it.
pub fn enabled_from_env() -> bool {
    std::env::var("PROMO_ID").as_deref() == Ok(PROMO_ID)
        && std::env::var("PROMO_DISABLED").as_deref() != Ok("1")
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicOffer {
    pub plan: &'static str,
    pub interval: &'static str,
    pub currency: &'static str,
    pub regular: i64,
    pub reference: i64,
    pub price: i64,
    pub percent_off: i64,
    /// Only the first paid month or year is discounted; renewals are regular.
    pub first_period_only: bool,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicPromo {
    pub server_time: String,
    pub id: Option<&'static str>,
    pub status: &'static str,
    pub starts_at: Option<&'static str>,
    pub ends_at: Option<&'static str>,
    pub offers: Vec<PublicOffer>,
}

/// The promotion as of `now`: off after the end or when not enabled, and no
/// prices published before the start.
pub fn promo_state(enabled: bool, now: DateTime<Utc>) -> PublicPromo {
    let mut state = PublicPromo {
        server_time: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        id: None,
        status: "disabled",
        starts_at: None,
        ends_at: None,
        offers: Vec::new(),
    };
    if !enabled || now >= at(ENDS_AT) {
        return state;
    }
    state.id = Some(PROMO_ID);
    state.starts_at = Some(STARTS_AT);
    state.ends_at = Some(ENDS_AT);
    if now < at(STARTS_AT) {
        state.status = "scheduled";
        return state;
    }
    state.status = "active";
    state.offers = OFFERS
        .iter()
        // A price that is not below its lawful reference is not a reduction
        // and is never shown as one.
        .filter(|o| o.price < o.reference && o.reference <= o.regular)
        .map(|o| PublicOffer {
            plan: o.plan.as_db_str(),
            interval: interval_str(o.interval),
            currency: "eur",
            regular: o.regular,
            reference: o.reference,
            price: o.price,
            percent_off: percent_off(o.reference, o.price),
            first_period_only: true,
        })
        .collect();
    state
}

/// The Stripe Checkout fields that apply the offer to one checkout, decided
/// from the server's clock and the plan the server resolved, never from the
/// client. Empty outside the window.
pub fn checkout_fields(
    enabled: bool,
    now: DateTime<Utc>,
    plan: Plan,
    interval: Interval,
) -> Vec<(String, String)> {
    let state = promo_state(enabled, now);
    let offered = state
        .offers
        .iter()
        .any(|o| o.plan == plan.as_db_str() && o.interval == interval_str(interval));
    if state.status != "active" || !offered {
        return Vec::new();
    }
    let mut fields = vec![
        ("discounts[0][coupon]".into(), coupon_id(plan, interval)),
        ("metadata[promo_id]".into(), PROMO_ID.into()),
        (
            "subscription_data[metadata][promo_id]".into(),
            PROMO_ID.into(),
        ),
    ];
    if let Some(expires_at) = expires_at(now) {
        fields.push(("expires_at".into(), expires_at.to_string()));
    }
    fields
}

/// The Checkout `expires_at` for a promotional session, or None to keep
/// Stripe's default of 24 hours. Stripe accepts 30 minutes to 24 hours after
/// creation, measured on its own clock, so neither bound is ever used
/// exactly: one extra minute at the short end, and the default whenever the
/// end is at least 23.5 hours away (a default session then still closes no
/// later than 30 minutes after the end).
pub fn expires_at(now: DateTime<Utc>) -> Option<i64> {
    let now_seconds = now.timestamp();
    let end_seconds = at(ENDS_AT).timestamp();
    (end_seconds - now_seconds < 23 * 3600 + 1800)
        .then(|| end_seconds.max(now_seconds + GRACE_SECONDS + 60))
}

/// GET /api/promo: public, uncached (every API response is no-store).
pub async fn public_promo() -> axum::Json<PublicPromo> {
    axum::Json(promo_state(enabled_from_env(), Utc::now()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn start() -> DateTime<Utc> {
        at(STARTS_AT)
    }
    fn end() -> DateTime<Utc> {
        at(ENDS_AT)
    }
    fn during() -> DateTime<Utc> {
        at("2026-10-31T20:00:00Z")
    }

    #[test]
    fn ends_at_one_minute_to_midnight_rome_time() {
        // Summer time ends on 25 October 2026 at 01:00 UTC, so on 6 November
        // Rome is on CET (UTC+1) and 23:00 UTC is its midnight.
        assert!(Utc.with_ymd_and_hms(2026, 10, 25, 1, 0, 0).unwrap() < end());
        let rome = chrono::FixedOffset::east_opt(3600).unwrap();
        let last = (end() - Duration::seconds(1)).with_timezone(&rome);
        assert_eq!(
            last.format("%d/%m/%Y %H:%M:%S").to_string(),
            "06/11/2026 23:59:59"
        );
    }

    /// Prices offered to the public, from the live Stripe Prices and every
    /// Glarion Checkout Session since August (UTC). [from, until, cents]
    fn history(plan: Plan, interval: Interval) -> Vec<(&'static str, Option<&'static str>, i64)> {
        match (plan, interval) {
            (Plan::Solo, Interval::Monthly) => vec![("2026-09-02T00:02:00Z", None, 1_900)],
            (Plan::Solo, Interval::Yearly) => vec![("2026-09-02T00:10:00Z", None, 17_000)],
            (Plan::Studio, Interval::Monthly) => vec![("2026-08-28T22:18:00Z", None, 3_900)],
            (Plan::Studio, Interval::Yearly) => vec![("2026-08-28T22:18:00Z", None, 35_000)],
            (Plan::Agency, Interval::Monthly) => vec![("2026-08-28T22:20:00Z", None, 9_900)],
            (Plan::Agency, Interval::Yearly) => vec![("2026-08-30T00:49:00Z", None, 75_000)],
            (Plan::Free, _) => vec![],
        }
    }

    fn lowest_before(plan: Plan, interval: Interval, start: DateTime<Utc>) -> i64 {
        let from = start - Duration::days(30);
        history(plan, interval)
            .into_iter()
            .filter(|(a, b, _)| at(a) < start && b.map(|b| at(b) > from).unwrap_or(true))
            .map(|(_, _, cents)| cents)
            .min()
            .unwrap()
    }

    /// The owner's rule: the highest whole-euro or ,99 amount at or under half
    /// the reference; from 100 euro, a multiple of 5.
    fn rounded_half(reference: i64) -> i64 {
        let half = reference as f64 / 2.0;
        if half >= 10_000.0 {
            return (half / 500.0).floor() as i64 * 500;
        }
        let whole = (half / 100.0).floor() as i64 * 100;
        let ninety_nine = ((half - 99.0) / 100.0).floor() as i64 * 100 + 99;
        whole.max(ninety_nine)
    }

    #[test]
    fn the_price_rule_rounds_down_to_round_figures() {
        let cases = [
            (799, 399),
            (7_990, 3_900),
            (1_499, 700),
            (14_990, 7_400),
            (1_900, 900),
            (17_000, 8_500),
            (35_000, 17_500),
            (25_000, 12_500),
        ];
        for (reference, price) in cases {
            assert_eq!(rounded_half(reference), price, "{reference}");
        }
    }

    #[test]
    fn every_struck_price_is_the_lowest_of_the_previous_thirty_days() {
        for o in OFFERS.iter() {
            assert_eq!(o.reference, lowest_before(o.plan, o.interval, start()));
            let mut t = start();
            while t < end() {
                assert!(o.reference <= lowest_before(o.plan, o.interval, t));
                t += Duration::hours(1);
            }
            assert_eq!(o.price, rounded_half(o.reference), "the price rule");
            assert!(percent_off(o.reference, o.price) >= 50);
        }
        let percents: Vec<i64> = OFFERS
            .iter()
            .map(|o| percent_off(o.reference, o.price))
            .collect();
        assert_eq!(percents, [52, 50, 51, 50, 50, 50]);
        assert_eq!(percent_off(1000, 801), 19, "rounded down, never up");
        // Every paid plan is on offer, in both intervals.
        for plan in crate::billing::PAID_PLANS {
            for interval in [Interval::Monthly, Interval::Yearly] {
                assert!(OFFERS
                    .iter()
                    .any(|o| o.plan == plan && o.interval == interval));
            }
        }
    }

    #[test]
    fn simulated_clock_nothing_before_every_offer_during_nothing_after() {
        assert_eq!(promo_state(false, during()).status, "disabled");
        let scheduled = promo_state(true, start() - Duration::seconds(1));
        assert_eq!(scheduled.status, "scheduled");
        assert!(scheduled.offers.is_empty(), "no price before the start");
        for now in [start(), during(), end() - Duration::milliseconds(1)] {
            let state = promo_state(true, now);
            assert_eq!(state.status, "active");
            assert_eq!(state.ends_at, Some(ENDS_AT));
            assert_eq!(state.offers.len(), 6);
            assert_eq!(
                state.offers[3],
                PublicOffer {
                    plan: "studio",
                    interval: "yearly",
                    currency: "eur",
                    regular: 35_000,
                    reference: 35_000,
                    price: 17_500,
                    percent_off: 50,
                    first_period_only: true
                }
            );
        }
        for now in [end(), end() + Duration::days(1), at("2027-10-31T12:00:00Z")] {
            let state = promo_state(true, now);
            assert_eq!(state.status, "disabled");
            assert!(state.id.is_none() && state.ends_at.is_none() && state.offers.is_empty());
        }
    }

    #[test]
    fn public_payload_is_camel_case_and_carries_no_stripe_ids() {
        let json = serde_json::to_string(&promo_state(true, during())).unwrap();
        assert!(json.contains("\"serverTime\":\"2026-10-31T20:00:00.000Z\""));
        assert!(json.contains("\"percentOff\":50") && json.contains("\"firstPeriodOnly\":true"));
        assert!(!json.contains("price_") && !json.contains("coupon") && !json.contains("sk_"));
    }

    #[test]
    fn checkout_gets_the_plans_own_coupon_only_inside_the_window() {
        let fields = checkout_fields(true, during(), Plan::Agency, Interval::Yearly);
        let get = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            get("discounts[0][coupon]"),
            Some("halloween50-2026-glarion-agency-yearly")
        );
        assert_eq!(get("metadata[promo_id]"), Some(PROMO_ID));
        assert_eq!(get("subscription_data[metadata][promo_id]"), Some(PROMO_ID));
        assert_eq!(
            checkout_fields(true, during(), Plan::Solo, Interval::Monthly)[0].1,
            "halloween50-2026-glarion-solo-monthly"
        );
        for now in [
            start() - Duration::seconds(1),
            end(),
            end() + Duration::days(7),
        ] {
            assert!(checkout_fields(true, now, Plan::Studio, Interval::Monthly).is_empty());
        }
        assert!(checkout_fields(false, during(), Plan::Studio, Interval::Monthly).is_empty());
        assert!(checkout_fields(true, during(), Plan::Free, Interval::Monthly).is_empty());
    }

    #[test]
    fn checkout_deadline_never_touches_stripes_limits_or_outlives_the_grace() {
        let mut now = start();
        while now < end() {
            let closes = match expires_at(now) {
                Some(at) => {
                    assert!(at >= now.timestamp() + GRACE_SECONDS + 60, "{now}");
                    assert!(at <= now.timestamp() + 23 * 3600 + 1800, "{now}");
                    at
                }
                None => now.timestamp() + 24 * 3600,
            };
            assert!(closes <= end().timestamp() + GRACE_SECONDS + 60, "{now}");
            now += Duration::minutes(7);
        }
        assert_eq!(
            expires_at(during()),
            None,
            "Stripe's default far from the end"
        );
        assert_eq!(
            expires_at(end() - Duration::hours(1)),
            Some(end().timestamp())
        );
        let fields = checkout_fields(
            true,
            end() - Duration::hours(1),
            Plan::Studio,
            Interval::Yearly,
        );
        assert!(fields
            .iter()
            .any(|(k, v)| k == "expires_at" && *v == end().timestamp().to_string()));
        let fields = checkout_fields(true, during(), Plan::Studio, Interval::Yearly);
        assert!(!fields.iter().any(|(k, _)| k == "expires_at"));
    }
}
