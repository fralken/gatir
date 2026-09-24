//! The proxy server: accepts clients and forwards their requests.

mod body;
mod failure;
mod forward;
mod headers;
mod server;
mod tunnel;

use std::io;

use tokio_util::sync::CancellationToken;

pub use server::Server;

use crate::config::Config;

/// Runs the proxy until the process is asked to stop (Ctrl-C or SIGTERM).
pub async fn run(config: &Config) -> io::Result<()> {
    let server = Server::bind(config).await?;
    for addr in server.local_addrs() {
        tracing::info!(%addr, "listening");
    }

    let shutdown = CancellationToken::new();
    let force = CancellationToken::new();
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
