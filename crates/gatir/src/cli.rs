//! Command-line interface.

use std::net::SocketAddr;
use std::path::PathBuf;

use std::io::BufRead;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::auth::ntlm::NtHash;

use crate::config::{AuthMethod, Config, LogLevel, Overrides, ParentAddr};
use crate::logging;

#[derive(Debug, Parser)]
#[command(name = "gatir", version, about, arg_required_else_help = true)]
pub struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub overrides: OverrideArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Options that take precedence over the configuration file.
#[derive(Debug, Args)]
pub struct OverrideArgs {
    /// Address to listen on; repeat for several (replaces `listen` from the file)
    #[arg(long, global = true, value_name = "ADDR")]
    pub listen: Vec<SocketAddr>,

    /// PAC file that chooses the proxy for each request (replaces `parents` from the file)
    #[arg(long, global = true, value_name = "FILE")]
    pub pac: Option<std::path::PathBuf>,

    /// Parent proxy as HOST:PORT; repeat for several (replaces `parents` or `[pac]` from the file)
    #[arg(long = "parent", global = true, value_name = "HOST:PORT")]
    pub parents: Vec<ParentAddr>,

    /// User name for the parent proxy
    #[arg(short, long, global = true)]
    pub username: Option<String>,

    /// Domain of the user
    #[arg(short, long, global = true)]
    pub domain: Option<String>,

    /// Authentication method
    #[arg(short, long, global = true, value_enum)]
    pub method: Option<AuthMethod>,

    /// Ask for the password on the terminal (replaces any password or hash from the file)
    #[arg(long, global = true)]
    pub password_prompt: bool,

    /// Log verbosity (the RUST_LOG environment variable takes precedence)
    #[arg(long, global = true, value_enum)]
    pub log_level: Option<LogLevel>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy until interrupted (Ctrl-C or SIGTERM)
    Run,

    /// Compute the NT hash of a password, to store in the configuration in its place
    Hash(HashArgs),

    /// Inspect the configuration
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Debug, Args)]
pub struct HashArgs {
    /// Read the password from standard input (one line) instead of asking on the terminal
    #[arg(long)]
    pub stdin: bool,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration and print a summary without secrets
    Check,
}

impl OverrideArgs {
    fn into_overrides(self, password: Option<SecretString>) -> Overrides {
        Overrides {
            listen: self.listen,
            parents: self.parents,
            pac: self.pac,
            username: self.username,
            domain: self.domain,
            method: self.method,
            password,
            log_level: self.log_level,
        }
    }
}

pub fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Hash(args) => hash_password(&args),
        Command::Run => {
            let config = load_config(cli.config.as_deref(), cli.overrides)?;
            if config.parents.is_empty() && config.pac.is_none() && config.credentials.is_some() {
                tracing::warn!(
                    "credentials are configured, but there is no parent proxy to authenticate to"
                );
            }
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("cannot start the async runtime")?
                .block_on(crate::proxy::run(&config))?;
            Ok(())
        }
        Command::Config(ConfigCommand::Check) => {
            let config = load_config(cli.config.as_deref(), cli.overrides)?;
            println!("configuration OK");
            println!("{}", config.summary());
            Ok(())
        }
    }
}

/// Reads the configuration, applies the command-line overrides and starts logging.
fn load_config(path: Option<&std::path::Path>, overrides: OverrideArgs) -> anyhow::Result<Config> {
    let password = if overrides.password_prompt {
        Some(prompt_password()?)
    } else {
        None
    };
    let config = Config::load(path, overrides.into_overrides(password))?;

    logging::init(config.log_level);
    tracing::debug!(?config, "configuration loaded");
    Ok(config)
}

/// Prints the `nt_hash` line to paste into the configuration. Only that line
/// goes to standard output, so it can be captured by a script.
fn hash_password(args: &HashArgs) -> anyhow::Result<()> {
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

fn prompt_password() -> anyhow::Result<SecretString> {
    let password = rpassword::prompt_password("Password: ").context("cannot read the password")?;
    Ok(SecretString::from(password))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn overrides_can_follow_the_subcommand() {
        let cli = Cli::try_parse_from([
            "gatir",
            "config",
            "check",
            "--config",
            "gatir.toml",
            "--listen",
            "127.0.0.1:8080",
            "--parent",
            "proxy.example.com:8080",
            "-u",
            "alice",
            "-m",
            "nt",
        ])
        .unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("gatir.toml")));
        assert_eq!(cli.overrides.listen.len(), 1);
        assert_eq!(cli.overrides.parents[0].port, 8080);
        assert_eq!(cli.overrides.username.as_deref(), Some("alice"));
        assert_eq!(cli.overrides.method, Some(AuthMethod::Nt));
    }

    #[test]
    fn the_password_is_never_taken_from_the_command_line() {
        // A password on the command line would be visible in the process list.
        assert!(Cli::try_parse_from(["gatir", "config", "check", "--password", "x"]).is_err());
        assert!(Cli::try_parse_from(["gatir", "config", "check", "-p", "x"]).is_err());

        let cli = Cli::try_parse_from(["gatir", "config", "check", "--password-prompt"]).unwrap();
        assert!(cli.overrides.password_prompt);
    }

    #[test]
    fn rejects_malformed_option_values() {
        for args in [
            ["--listen", "nope"],
            ["--parent", "no-port"],
            ["--method", "kerberos"],
            ["--log-level", "loud"],
        ] {
            let mut argv = vec!["gatir", "config", "check"];
            argv.extend(args);
            assert!(Cli::try_parse_from(argv).is_err(), "{args:?}");
        }
    }
}
