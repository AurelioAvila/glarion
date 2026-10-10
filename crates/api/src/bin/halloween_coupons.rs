//! Creates (or checks) the Stripe coupons behind `api::promo`, through the
//! Stripe CLI, so no secret key is ever handled here:
//!
//! ```text
//! cargo run -p api --bin halloween_coupons                      # test mode, check only
//! cargo run -p api --bin halloween_coupons -- --apply           # test mode, create missing
//! cargo run -p api --bin halloween_coupons -- --live --verify-session
//! ```
//!
//! The STRIPE_PRICE_* variables name the Prices of the chosen mode (price
//! IDs are not secrets). Coupon IDs are fixed, so a rerun creates nothing
//! twice. `--verify-session` opens one unpaid Checkout per coupon with the
//! discount, checks Stripe's totals and expires it at once: nothing is
//! charged. Only after every line reads "ok" may `PROMO_ID=halloween50-2026`
//! be set on the deployment; unset it (or set PROMO_DISABLED=1) to stop.
//! Not built into the image (the Dockerfile names its binaries).

use api::billing::price_env_var;
use api::promo::{coupon_id, interval_str, ENDS_AT, GRACE_SECONDS, OFFERS, PROMO_ID};
use serde_json::Value;
use std::process::{Command, ExitCode};

fn stripe(live: bool, args: &[&str]) -> Value {
    let mut command = Command::new("stripe");
    command.args(args);
    if live {
        command.arg("--live");
    }
    let output = command
        .output()
        .expect("the Stripe CLI is installed and on PATH");
    let text = String::from_utf8_lossy(&output.stdout);
    // The CLI prefixes some answers with a mode banner; the JSON follows it.
    match (text.find('{'), text.rfind('}')) {
        (Some(start), Some(end)) => {
            serde_json::from_str(&text[start..=end]).expect("Stripe CLI JSON")
        }
        _ => panic!(
            "stripe {} returned nothing: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

fn main() -> ExitCode {
    let flags: Vec<String> = std::env::args().skip(1).collect();
    let live = flags.iter().any(|f| f == "--live");
    let apply = flags.iter().any(|f| f == "--apply");
    let verify = flags.iter().any(|f| f == "--verify-session");
    let end: chrono::DateTime<chrono::Utc> = ENDS_AT.parse().expect("valid end");
    // The server stops discounting at the end; a checkout opened just before
    // stays payable for the grace period, so the coupon outlives it slightly.
    let redeem_by = end.timestamp() + GRACE_SECONDS + 300;
    let mut failed = false;
    println!(
        "{} mode, {}",
        if live { "LIVE" } else { "TEST" },
        if apply { "apply" } else { "check only" }
    );

    for offer in OFFERS.iter() {
        let var = price_env_var(offer.plan, offer.interval).expect("paid plan");
        let Ok(price_id) = std::env::var(var) else {
            eprintln!("FAIL {var} is not set");
            failed = true;
            continue;
        };
        let price = stripe(live, &["prices", "retrieve", &price_id]);
        if price["unit_amount"].as_i64() != Some(offer.regular)
            || price["currency"] != "eur"
            || price["livemode"].as_bool() != Some(live)
            || price["active"].as_bool() != Some(true)
        {
            eprintln!(
                "FAIL {var} is {} {}, expected {} eur",
                price["unit_amount"], price["currency"], offer.regular
            );
            failed = true;
            continue;
        }
        let product = price["product"].as_str().unwrap_or_default().to_string();
        let id = coupon_id(offer.plan, offer.interval);
        let amount_off = offer.regular - offer.price;

        let mut coupon = stripe(
            live,
            &["coupons", "retrieve", &id, "-d", "expand[]=applies_to"],
        );
        if coupon["error"]["code"] == "resource_missing" {
            if !apply {
                eprintln!("FAIL {id} does not exist (run with --apply)");
                failed = true;
                continue;
            }
            let fields = [
                format!("id={id}"),
                format!("amount_off={amount_off}"),
                "currency=eur".into(),
                "duration=once".into(),
                format!("redeem_by={redeem_by}"),
                format!("applies_to[products][0]={product}"),
                "name=Halloween offer".into(),
                format!("metadata[promo]={PROMO_ID}"),
                "metadata[product]=glarion".into(),
                format!("metadata[plan]={}", offer.plan.as_db_str()),
                format!("metadata[interval]={}", interval_str(offer.interval)),
                "expand[]=applies_to".into(),
            ];
            let mut args = vec!["coupons", "create"];
            for field in &fields {
                args.extend(["-d", field.as_str()]);
            }
            coupon = stripe(live, &args);
            println!("created {id}");
        }
        if !coupon["error"].is_null() {
            eprintln!("FAIL {id}: {}", coupon["error"]["message"]);
            failed = true;
            continue;
        }
        let products = coupon["applies_to"]["products"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if coupon["amount_off"].as_i64() != Some(amount_off)
            || coupon["currency"] != "eur"
            || coupon["duration"] != "once"
            || coupon["redeem_by"].as_i64() != Some(redeem_by)
            || coupon["valid"].as_bool() != Some(true)
            || coupon["livemode"].as_bool() != Some(live)
            || products.len() != 1
            || products[0] != product.as_str()
        {
            eprintln!("FAIL {id} does not match api::promo; delete it in Stripe only while PROMO_ID is unset");
            failed = true;
            continue;
        }
        println!(
            "ok   {id}  ({} -> {} cents, redeem by {})",
            offer.regular,
            offer.price,
            chrono::DateTime::from_timestamp(redeem_by, 0)
                .unwrap()
                .to_rfc3339()
        );

        if verify {
            let fields = [
                "mode=subscription".to_string(),
                format!("line_items[0][price]={price_id}"),
                "line_items[0][quantity]=1".into(),
                format!("discounts[0][coupon]={id}"),
                "automatic_tax[enabled]=true".into(),
                "success_url=https://glarion.app/app/#/plan".into(),
                "cancel_url=https://glarion.app/app/#/plan".into(),
                format!(
                    "expires_at={}",
                    chrono::Utc::now().timestamp() + GRACE_SECONDS + 60
                ),
                format!("metadata[promo_verification]={PROMO_ID}"),
            ];
            let mut args = vec!["checkout", "sessions", "create"];
            for field in &fields {
                args.extend(["-d", field.as_str()]);
            }
            let session = stripe(live, &args);
            let Some(session_id) = session["id"].as_str() else {
                eprintln!("FAIL {id} checkout: {}", session["error"]["message"]);
                failed = true;
                continue;
            };
            stripe(live, &["checkout", "sessions", "expire", session_id]);
            let subtotal = session["amount_subtotal"].as_i64();
            let discount = session["total_details"]["amount_discount"].as_i64();
            if subtotal != Some(offer.regular) || discount != Some(amount_off) {
                eprintln!("FAIL {id} checkout quoted {subtotal:?} - {discount:?}");
                failed = true;
            } else {
                println!(
                    "     checkout {}… quoted {} - {} = {} before tax, expired",
                    &session_id[..16],
                    offer.regular,
                    amount_off,
                    offer.price
                );
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
