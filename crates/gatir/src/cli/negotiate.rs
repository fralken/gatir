//! `gatir negotiate`: what the system gives for a Negotiate token.

use clap::Args;

#[derive(Debug, Args)]
pub struct NegotiateArgs {
    /// The service of the parent proxy: `HTTP@proxy.example.com`, or a Kerberos
    /// principal such as `HTTP/proxy.example.com@EXAMPLE.COM`
    #[arg(long, value_name = "SERVICE")]
    pub service: String,
}

pub(super) fn run(args: &NegotiateArgs) -> anyhow::Result<()> {
    negotiate_check(args)
}

/// Asks the system for a token, and prints what it is.
fn negotiate_check(args: &NegotiateArgs) -> anyhow::Result<()> {
    let tokens = crate::auth::system_tokens()?;
    let diagnosis = crate::auth::diagnose(tokens.as_ref(), &args.service)?;
    println!("service:     {}", args.service);
    println!("token:       {} bytes", diagnosis.token_bytes);
    if diagnosis.mechanisms.is_empty() {
        println!("mechanisms:  none that gatir recognizes");
    } else {
        println!("mechanisms:  {}", diagnosis.mechanisms.join(", "));
    }
    println!(
        "answer:      gatir asks nothing until the parent's 407 asks for Negotiate; then this"
    );
    if diagnosis.complete {
        println!("             token goes with the request, and nothing more is needed");
    } else {
        println!("             token goes with the request, and gatir answers a challenge if the");
        println!(
            "             parent sends one (NTLM inside Negotiate works this way; a parent that"
        );
        println!("             accepts a Kerberos ticket at once needs nothing more)");
    }
    Ok(())
}
