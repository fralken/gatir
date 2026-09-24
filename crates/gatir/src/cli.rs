//! Command-line interface.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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

    /// Parent proxy as HOST:PORT; repeat for several (replaces `parents` from the file)
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

    /// Log verbosity (the RUST_LOG environment variable takes precedence)
    #[arg(long, global = true, value_enum)]
    pub log_level: Option<LogLevel>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect the configuration
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration and print a summary without secrets
    Check,
}

impl OverrideArgs {
    fn into_overrides(self) -> Overrides {
        Overrides {
            listen: self.listen,
            parents: self.parents,
            username: self.username,
            domain: self.domain,
            method: self.method,
            password: None,
            log_level: self.log_level,
        }
    }
}

pub fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(cli.config.as_deref(), cli.overrides.into_overrides())?;

    logging::init(config.log_level);
    tracing::debug!(?config, "configuration loaded");

    match cli.command {
        Command::Config(ConfigCommand::Check) => {
            println!("configuration OK");
            println!("{}", config.summary());
        }
    }
    Ok(())
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
    fn there_is_no_password_flag() {
        // A password on the command line would be visible in the process list.
        assert!(Cli::try_parse_from(["gatir", "config", "check", "--password", "x"]).is_err());
        assert!(Cli::try_parse_from(["gatir", "config", "check", "-p", "x"]).is_err());
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
