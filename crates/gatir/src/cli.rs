//! Command-line interface.

use std::net::SocketAddr;
use std::path::PathBuf;

use std::io::BufRead;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use hyper::Uri;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::auth::ntlm::NtHash;

use crate::config::{AuthMethod, Config, HostPort, LogLevel, Overrides, Tunnel};
use crate::logging;
use crate::proxy::AttemptOutcome;

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
#[derive(Debug, Clone, Args)]
pub struct OverrideArgs {
    /// Address to listen on; repeat for several (replaces `listen` from the file)
    #[arg(long, global = true, value_name = "ADDR")]
    pub listen: Vec<SocketAddr>,

    /// PAC file or http(s) address that chooses the proxy for each request (replaces `parents` from the file)
    #[arg(long, global = true, value_name = "FILE|URL")]
    pub pac: Option<crate::config::PacLocation>,

    /// Parent proxy as HOST:PORT; repeat for several (replaces `parents` or `[pac]` from the file)
    #[arg(long = "parent", global = true, value_name = "HOST:PORT")]
    pub parents: Vec<HostPort>,

    /// A destination reached directly instead of through a proxy: a host name
    /// (with `*`/`?`), an IP address or a CIDR range; repeat for several
    /// (replaces `no_proxy` from the file)
    #[arg(long, global = true, value_name = "HOST")]
    pub no_proxy: Vec<String>,

    /// User name for the parent proxy
    #[arg(short, long, global = true)]
    pub username: Option<String>,

    /// Domain of the user
    #[arg(short, long, global = true)]
    pub domain: Option<String>,

    /// Authentication method
    #[arg(short, long, global = true, value_enum)]
    pub method: Option<AuthMethod>,

    /// Forward a local port to a destination through the proxy, as in OpenSSH: [BIND:]PORT:HOST:HOSTPORT;
    /// repeat for several (replaces `[[tunnels]]` from the file)
    #[arg(short = 'L', long = "tunnel", global = true, value_name = "SPEC")]
    pub tunnels: Vec<Tunnel>,

    /// Address for a SOCKS5 server; repeat for several (replaces `[socks5] listen` from the file)
    #[arg(long, global = true, value_name = "ADDR")]
    pub socks5: Vec<SocketAddr>,

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

    /// Ask the system for a Negotiate token for a service, and say what it is:
    /// to find out why Kerberos or NTLM single sign-on does not work
    Negotiate(NegotiateArgs),

    /// Probe a real parent proxy for what it offers, and, if credentials are
    /// configured, which one it accepts: unlike `negotiate`, this contacts it
    Detect(DetectArgs),
}

#[derive(Debug, Args)]
pub struct DetectArgs {
    /// The request to send, exactly as a real client would ask for it
    #[arg(long, value_name = "URL")]
    pub url: Uri,
}

#[derive(Debug, Args)]
pub struct NegotiateArgs {
    /// The service of the parent proxy: `HTTP@proxy.example.com`, or a Kerberos
    /// principal such as `HTTP/proxy.example.com@EXAMPLE.COM`
    #[arg(long, value_name = "SERVICE")]
    pub service: String,
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
    /// The overrides for reading the configuration. `password` is copied: they
    /// are made again at every reload.
    fn to_overrides(&self, password: Option<&SecretString>) -> Overrides {
        let password =
            password.map(|password| SecretString::from(password.expose_secret().to_owned()));
        let this = self.clone();
        Overrides {
            listen: this.listen,
            parents: this.parents,
            pac: this.pac,
            username: this.username,
            domain: this.domain,
            method: this.method,
            password,
            tunnels: this.tunnels,
            socks5: this.socks5,
            no_proxy: this.no_proxy,
            log_level: this.log_level,
        }
    }
}

pub fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Hash(args) => hash_password(&args),
        Command::Run => {
            let source = Source::new(cli.config, cli.overrides)?;
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
        Command::Negotiate(args) => negotiate_check(&args),
        Command::Detect(args) => {
            let source = Source::new(cli.config, cli.overrides)?;
            let config = load_config(&source)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("cannot start the async runtime")?
                .block_on(detect_check(&config, &args))
        }
        Command::Config(ConfigCommand::Check) => {
            let source = Source::new(cli.config, cli.overrides)?;
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
        config.timeouts.connect,
        config.timeouts.response,
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

/// Where the configuration comes from, so that it can be read again: the file,
/// and what the command line says on top of it.
struct Source {
    /// The file named, or else the first that is found in the usual places;
    /// `None` if there is none, and the defaults apply.
    file: Option<PathBuf>,
    overrides: OverrideArgs,
    /// A password typed at the start, which the command line cannot carry.
    password: Option<SecretString>,
}

impl Source {
    fn new(path: Option<PathBuf>, overrides: OverrideArgs) -> anyhow::Result<Self> {
        let password = if overrides.password_prompt {
            Some(prompt_password()?)
        } else {
            None
        };
        Ok(Self {
            file: path.or_else(crate::config::default_path),
            overrides,
            password,
        })
    }

    fn read(&self) -> Result<Config, crate::config::ConfigError> {
        Config::load(
            self.file.as_deref(),
            self.overrides.to_overrides(self.password.as_ref()),
        )
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
