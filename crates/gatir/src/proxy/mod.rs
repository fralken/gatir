//! The proxy server: accepts clients and forwards their requests.

mod body;
mod detect;
mod failure;
mod forward;
mod headers;
mod parent;
mod pool;
mod portfwd;
mod server;
mod socks5;
mod tunnel;
mod upstream;

use std::io;

use tokio_util::sync::CancellationToken;

pub use detect::{Attempt, AttemptOutcome, Probe, Report, run as detect};
pub use server::{Reloader, Server};

use crate::config::{Config, ConfigError};

/// Reads the configuration again, for a reload.
pub type Loader = Box<dyn Fn() -> Result<Config, ConfigError> + Send + Sync>;

/// Runs the proxy until the process is asked to stop (Ctrl-C or SIGTERM).
///
/// On SIGHUP, `load` is called for the configuration as it is now, and its
/// settings replace those in use; see [`Reloader::apply`] for what that changes.
/// A configuration that cannot be read, or applied, changes nothing.
pub async fn run(config: &Config, load: Loader) -> io::Result<()> {
    let server = Server::bind(config).await?;
    // Registered before anything else can happen: a SIGHUP that arrives while
    // no one is looking for it ends the process.
    #[cfg(unix)]
    let hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let reloader = server.reloader();
    for addr in server.local_addrs() {
        tracing::info!(%addr, "listening");
    }
    for (addr, target) in server.tunnel_addrs() {
        tracing::info!(%addr, %target, "forwarding a port");
    }
    for addr in server.socks5_addrs() {
        tracing::info!(%addr, "SOCKS5 listening");
    }

    let shutdown = CancellationToken::new();
    let force = CancellationToken::new();
    #[cfg(unix)]
    tokio::spawn(reload_on_hangup(hangup, reloader, load, shutdown.clone()));
    #[cfg(not(unix))]
    let _ = (reloader, load);
    tokio::spawn({
        let shutdown = shutdown.clone();
        let force = force.clone();
        async move {
            if let Err(err) = wait_for_signal().await {
                tracing::error!(%err, "cannot listen for shutdown signals");
                shutdown.cancel();
                return;
            }
            tracing::info!("shutdown requested; interrupt again to close everything now");
            shutdown.cancel();

            if wait_for_signal().await.is_ok() {
                tracing::warn!("second interrupt, closing everything now");
            }
            force.cancel();
        }
    });

    server.run(shutdown, force).await;
    Ok(())
}

/// Applies the configuration again every time the process is hung up on.
#[cfg(unix)]
async fn reload_on_hangup(
    mut hangup: tokio::signal::unix::Signal,
    reloader: Reloader,
    load: Loader,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            signal = hangup.recv() => if signal.is_none() { return },
        }
        tracing::info!("SIGHUP received, reading the configuration again");
        reload(&reloader, &load).await;
    }
}

/// One reload: reads the configuration, applies it, and says how it went. What
/// goes wrong leaves the settings in use as they are.
pub async fn reload(reloader: &Reloader, load: &Loader) {
    let config = match load() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(%err, "the configuration is not valid, keeping the settings in use");
            return;
        }
    };
    match reloader.apply(&config).await {
        Ok(pending) => {
            tracing::info!("configuration reloaded");
            tracing::debug!("configuration summary\n{}", config.summary());
            if !pending.is_empty() {
                tracing::warn!(
                    settings = %pending.join(", "),
                    "these settings changed, and take effect only when gatir is started again"
                );
            }
        }
        Err(err) => tracing::error!(
            %err,
            "the new configuration cannot be applied, keeping the settings in use"
        ),
    }
}

#[cfg(unix)]
async fn wait_for_signal() -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}
