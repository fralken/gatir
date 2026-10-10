//! `gatir detect`: what a real parent proxy offers, and which of the configured
//! credentials it accepts.

use anyhow::Context;
use clap::Args;
use hyper::Uri;

use crate::config::Config;
use crate::proxy::AttemptOutcome;

#[derive(Debug, Args)]
pub struct DetectArgs {
    /// The request to send, exactly as a real client would ask for it
    #[arg(long, value_name = "URL")]
    pub url: Uri,
}

pub(super) fn run(config: &Config, args: &DetectArgs) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?
        .block_on(detect_check(config, args))
}

/// Contacts a real parent proxy for `args.url`, and, with credentials
/// configured, tries them for real: each attempt is a real login against the
/// account behind them, so this is not repeated on its own.
async fn detect_check(config: &Config, args: &DetectArgs) -> anyhow::Result<()> {
    let parent = config.parents.first().ok_or_else(|| {
        anyhow::anyhow!(
            "gatir detect needs a parent to test: pass --parent HOST:PORT (a PAC script, if \
             configured, is not evaluated by this command)"
        )
    })?;
    println!("parent:      {parent}");
    if config.parents.len() > 1 {
        println!(
            "             (the first of {} configured; the others are not tried)",
            config.parents.len()
        );
    }
    println!("url:         {}", args.url);

    let report = crate::proxy::detect(
        parent,
        &args.url,
        config.credentials.as_ref(),
        &config.timeouts,
        None,
    )
    .await
    .map_err(|message| anyhow::anyhow!(message))?;

    if report.probe.status == 407 {
        println!("probe:       HTTP 407 (authentication required)");
    } else {
        println!(
            "probe:       HTTP {} (no authentication needed)",
            report.probe.status
        );
    }
    if !report.probe.offers.is_empty() {
        println!("offers:      {}", report.probe.offers.join(", "));
    }
    if report.probe.status != 407 {
        return Ok(());
    }

    if report.attempts.is_empty() {
        match &config.credentials {
            None => println!(
                "no credentials are configured: pass -u/-d/-m/--password-prompt, or set \
                 [credentials], to try them against this parent"
            ),
            Some(credentials) => println!(
                "credentials.method is \"{}\", but this parent does not offer it: nothing to try",
                credentials.method.as_str()
            ),
        }
        return Ok(());
    }

    let mut accepted = None;
    for attempt in &report.attempts {
        match &attempt.outcome {
            AttemptOutcome::Accepted => {
                println!("trying {}... accepted", attempt.method);
                accepted = Some(attempt.method);
            }
            AttemptOutcome::Rejected => println!("trying {}... rejected", attempt.method),
            AttemptOutcome::Failed(reason) => {
                println!("trying {}... failed: {reason}", attempt.method);
            }
        }
    }
    println!("----------------------------------------");
    match accepted {
        Some(method) => println!(
            "gatir can authenticate to this parent with the configured credentials using \
             method = \"{method}\"."
        ),
        None => println!(
            "none of the attempts were accepted: check the user name, domain and password, or \
             that this account is allowed through this parent."
        ),
    }
    Ok(())
}
