//! Command-line interface: the definition of the commands, and the one that
//! runs them. What each command does is in a module of its own.

mod detect;
mod hash;
mod negotiate;
mod pac;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use secrecy::SecretString;

use crate::config::{Config, Overrides};
use crate::logging;

pub use detect::DetectArgs;
pub use hash::HashArgs;
pub use negotiate::NegotiateArgs;
pub use pac::{GenerateArgs, PacCommand, TestArgs};

#[derive(Debug, Parser)]
#[command(name = "gatir", version, about, arg_required_else_help = true)]
pub struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub overrides: Overrides,

    /// Ask for the password on the terminal (replaces any password or hash from the file)
    #[arg(long, global = true)]
    pub password_prompt: bool,

    #[command(subcommand)]
    pub command: Command,
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

    /// Ask the system for a Negotiate token for a service, and say what it is:
    /// to find out why Kerberos or NTLM single sign-on does not work
    Negotiate(NegotiateArgs),

    /// Probe a real parent proxy for what it offers, and, if credentials are
    /// configured, which one it accepts: unlike `negotiate`, this contacts it
    Detect(DetectArgs),

    /// Make a PAC script copy with local routes, and see what a script answers
    #[command(subcommand)]
    Pac(PacCommand),
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration and print a summary without secrets
    Check,
}

pub fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Hash(args) => hash::run(&args),
        Command::Negotiate(args) => negotiate::run(&args),
        Command::Pac(command) => pac::run(command, cli.config, cli.overrides, cli.password_prompt),
        Command::Detect(args) => {
            let source = Source::new(cli.config, cli.overrides, cli.password_prompt)?;
            let config = load_config(&source)?;
            detect::run(&config, &args)
        }
        Command::Run => {
            let source = Source::new(cli.config, cli.overrides, cli.password_prompt)?;
            let config = load_config(&source)?;
            if config.parents.is_empty()
                && config.pac.is_none()
                && config
                    .credentials
                    .as_ref()
                    .is_some_and(|credentials| credentials.origin_hosts.entries().is_empty())
            {
                tracing::warn!(
                    "credentials are configured, but there is no parent proxy to authenticate to"
                );
            }
            // The configuration is read the same way at every SIGHUP.
            let load: crate::proxy::Loader = Box::new(move || source.read());
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("cannot start the async runtime")?
                .block_on(crate::proxy::run(&config, load))?;
            Ok(())
        }
        Command::Config(ConfigCommand::Check) => {
            let source = Source::new(cli.config, cli.overrides, cli.password_prompt)?;
            let config = load_config(&source)?;
            println!("configuration OK");
            match &source.file {
                Some(file) => println!("file:        {}", file.display()),
                None => println!("file:        none (built-in defaults)"),
            }
            println!("{}", config.summary());
            Ok(())
        }
    }
}

/// Where the configuration comes from, so that it can be read again: the file,
/// and what the command line says on top of it.
struct Source {
    /// The file named, or else the first that is found in the usual places;
    /// `None` if there is none, and the defaults apply.
    file: Option<PathBuf>,
    /// The command line, with the password typed at the start, which the
    /// command line cannot carry.
    overrides: Overrides,
}

impl Source {
    fn new(
        path: Option<PathBuf>,
        mut overrides: Overrides,
        password_prompt: bool,
    ) -> anyhow::Result<Self> {
        if password_prompt {
            overrides.password = Some(prompt_password()?);
        }
        Ok(Self {
            file: path.or_else(crate::config::default_path),
            overrides,
        })
    }

    fn read(&self) -> Result<Config, crate::config::ConfigError> {
        Config::load(self.file.as_deref(), self.overrides.clone())
    }
}

/// Reads the configuration for the first time, and starts logging.
fn load_config(source: &Source) -> anyhow::Result<Config> {
    let config = source.read()?;

    logging::init(config.log_level);
    match &source.file {
        Some(file) => {
            tracing::info!(file = %file.display(), "configuration file");
            if let Some(problem) = crate::config::exposure(file, config.holds_secrets()) {
                tracing::warn!(
                    file = %file.display(),
                    "the configuration file {problem}: restrict it to its owner (chmod 600)"
                );
            }
        }
        None => tracing::info!("no configuration file: using the built-in defaults"),
    }
    tracing::debug!("configuration loaded\n{}", config.summary());
    Ok(config)
}

fn prompt_password() -> anyhow::Result<SecretString> {
    let password = rpassword::prompt_password("Password: ").context("cannot read the password")?;
    Ok(SecretString::from(password))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use crate::config::AuthMethod;

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
        assert!(cli.password_prompt);
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
