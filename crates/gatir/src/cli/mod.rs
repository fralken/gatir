//! Command-line interface: the definition of the commands, and the one that
//! runs them. What each command does is in a module of its own.

mod detect;
mod hash;
mod negotiate;
mod pac;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use secrecy::SecretString;

use crate::config::{Config, Overrides};
use crate::logging;

pub use detect::DetectArgs;
pub use hash::HashArgs;
pub use negotiate::NegotiateArgs;
pub use pac::{ExportArgs, PacCommand, TestArgs};

#[derive(Debug, Parser)]
#[command(name = "gatir", version, about, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Where the configuration comes from: the options of the commands that read
/// it, and only of those.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Path to the TOML configuration file (by default, the first found in the
    /// places listed under FILES in gatir(1))
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub overrides: Overrides,

    /// Ask for the password on the terminal (replaces any password or hash from the file)
    #[arg(long, global = true)]
    pub password_prompt: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy until interrupted (Ctrl-C or SIGTERM)
    Run(ConfigArgs),

    /// Compute the NT hash of a password, to store in the configuration in its place
    Hash(HashArgs),

    /// Inspect the configuration
    Config {
        #[command(flatten)]
        source: ConfigArgs,
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Ask the system for a Negotiate token for a service, and say what it is:
    /// to find out why Kerberos or NTLM single sign-on does not work
    Negotiate(NegotiateArgs),

    /// Probe a real parent proxy for what it offers, and, if credentials are
    /// configured, which one it accepts: unlike `negotiate`, this contacts it
    ///
    /// Each attempt with the credentials is a real login: if the password is
    /// wrong, it counts toward locking the account.
    Detect {
        #[command(flatten)]
        source: ConfigArgs,
        #[command(flatten)]
        args: DetectArgs,
    },

    /// Write the PAC script gatir runs, with its overrides, and see what a script answers
    Pac {
        #[command(flatten)]
        source: ConfigArgs,
        #[command(subcommand)]
        command: PacCommand,
    },
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
        Command::Pac { source, command } => pac::run(command, source),
        Command::Detect { source, args } => {
            let source = Source::new(source)?;
            let config = load_config(&source)?;
            detect::run(&config, &args)
        }
        Command::Run(source) => {
            let source = Source::new(source)?;
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
        Command::Config {
            source,
            command: ConfigCommand::Check,
        } => {
            let source = Source::new(source)?;
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
    fn new(args: ConfigArgs) -> anyhow::Result<Self> {
        let ConfigArgs {
            config,
            mut overrides,
            password_prompt,
        } = args;
        if password_prompt {
            overrides.password = Some(prompt_password()?);
        }
        Ok(Self {
            file: config.or_else(crate::config::default_path),
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

    /// The configuration options of `config check`.
    fn config_check(args: &[&str]) -> ConfigArgs {
        let mut argv = vec!["gatir", "config", "check"];
        argv.extend(args);
        match Cli::try_parse_from(argv).unwrap().command {
            Command::Config { source, .. } => source,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn overrides_follow_the_subcommand() {
        let source = config_check(&[
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
        ]);
        assert_eq!(source.config, Some(PathBuf::from("gatir.toml")));
        assert_eq!(source.overrides.listen.len(), 1);
        assert_eq!(source.overrides.parents[0].port, 8080);
        assert_eq!(source.overrides.username.as_deref(), Some("alice"));
        assert_eq!(source.overrides.method, Some(AuthMethod::Nt));
    }

    #[test]
    fn a_group_of_commands_takes_them_before_or_after_its_command() {
        for argv in [
            ["gatir", "pac", "--config", "gatir.toml", "export"],
            ["gatir", "pac", "export", "--config", "gatir.toml"],
        ] {
            match Cli::try_parse_from(argv).unwrap().command {
                Command::Pac { source, .. } => {
                    assert_eq!(source.config, Some(PathBuf::from("gatir.toml")));
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn commands_that_do_not_read_the_configuration_refuse_its_options() {
        for argv in [
            vec!["gatir", "hash", "--stdin", "--listen", "127.0.0.1:1"],
            vec!["gatir", "hash", "--config", "gatir.toml"],
            vec![
                "gatir",
                "negotiate",
                "--service",
                "HTTP@p",
                "--parent",
                "p:1",
            ],
            vec![
                "gatir",
                "negotiate",
                "--service",
                "HTTP@p",
                "--password-prompt",
            ],
            // Before the command, they belong to no command at all.
            vec!["gatir", "--config", "gatir.toml", "run"],
        ] {
            assert!(Cli::try_parse_from(&argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn the_password_is_never_taken_from_the_command_line() {
        // A password on the command line would be visible in the process list.
        assert!(Cli::try_parse_from(["gatir", "config", "check", "--password", "x"]).is_err());
        assert!(Cli::try_parse_from(["gatir", "config", "check", "-p", "x"]).is_err());

        assert!(config_check(&["--password-prompt"]).password_prompt);
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
