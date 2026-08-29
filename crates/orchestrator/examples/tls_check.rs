//! Reads one domain's certificate and prints what would be reported.
//!
//!   cargo run -p orchestrator --example tls_check -- expired.badssl.com
//!
//! A development aid, not part of the product: the scan path goes through
//! the runner and the ownership gate. This talks to whatever you name, so
//! point it at your own hosts or at the badssl.com endpoints, which exist
//! to be pointed at.

#[tokio::main]
async fn main() {
    let domain = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: tls_check <domain>");
        std::process::exit(2);
    });

    match orchestrator::tools::tls::run(&domain).await {
        Ok(findings) => {
            println!("{domain}: {} finding(s)", findings.len());
            for finding in findings {
                println!(
                    "  [{:?}] {}\n      {}",
                    finding.severity,
                    finding.title,
                    finding.description.unwrap_or_default()
                );
            }
        }
        Err(err) => println!("{domain}: {err}"),
    }
}
