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
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            match wait_for_signal().await {
                Ok(()) => tracing::info!("shutdown requested"),
                Err(err) => tracing::error!(%err, "cannot listen for shutdown signals"),
            }
            shutdown.cancel();
        }
    });

    server.run(shutdown).await;
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
