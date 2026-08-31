//! Confirms fetch_dns_txt_records still does a real lookup after the
//! hickory-resolver 0.26 API rewrite. Prepends `_glarion-verify.` itself
//! (the same as the function under test), so pass a bare domain.
//!
//!   cargo run -p orchestrator --example dns_check -- google.com

#[tokio::main]
async fn main() {
    let domain = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "google.com".to_string());
    match orchestrator::verification::fetch_dns_txt_records(&domain).await {
        Ok(records) => {
            println!(
                "{} TXT record(s) for _glarion-verify.{domain}:",
                records.len()
            );
            for record in records {
                println!("  {record}");
            }
        }
        Err(err) => println!("error: {err}"),
    }
}
