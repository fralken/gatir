//! `gatir hash`: the hash of a password, to keep in the configuration in its
//! place.

use std::io::BufRead;

use anyhow::Context;
use clap::Args;
use zeroize::Zeroizing;

use crate::auth::ntlm::NtHash;

#[derive(Debug, Args)]
pub struct HashArgs {
    /// Read the password from standard input (one line) instead of asking on the terminal
    #[arg(long)]
    pub stdin: bool,
}

/// Prints the `nt_hash` line to paste into the configuration. Only that line
/// goes to standard output, so it can be captured by a script.
pub(super) fn run(args: &HashArgs) -> anyhow::Result<()> {
    let password = if args.stdin {
        read_password_line()?
    } else {
        let first = Zeroizing::new(
            rpassword::prompt_password("Password: ").context("cannot read the password")?,
        );
        let second = Zeroizing::new(
            rpassword::prompt_password("Confirm password: ").context("cannot read the password")?,
        );
        anyhow::ensure!(*first == *second, "the two passwords are different");
        first
    };
    anyhow::ensure!(!password.is_empty(), "the password is empty");

    println!(
        "nt_hash = \"{}\"",
        NtHash::from_password(&password).to_hex()
    );
    eprintln!(
        "Put this line in the [credentials] table of your configuration, in place of `password`."
    );
    Ok(())
}

/// One line from standard input, without its line ending.
fn read_password_line() -> anyhow::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("cannot read the password from standard input")?;
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line)
}
