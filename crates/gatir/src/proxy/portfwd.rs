//! Static tunnels: a local port whose every connection is carried to one fixed
//! destination, straight or through the parent proxy the configuration chooses.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::header::HeaderMap;
use hyper::http::Extensions;
use tokio::net::TcpStream;

use super::server::Context;
use super::tunnel::{self, Reached};
use crate::config::HostPort;

/// Carries one client to `target`. A client that cannot be served is simply
/// disconnected: there is no protocol here to say why, so the reason goes to
/// the log.
pub(super) async fn serve(
    client: TcpStream,
    peer: SocketAddr,
    target: HostPort,
    context: Arc<Context>,
) {
    if let Err(err) = client.set_nodelay(true) {
        tracing::debug!(%peer, %err, "cannot set TCP_NODELAY on the client connection");
    }
    let reached = tunnel::reach(
        &context,
        &target.host_in_url(),
        target.port,
        HeaderMap::new(),
        Extensions::new(),
    )
    .await;
    match reached {
        Ok(Reached::Open(upstream)) => {
            tracing::debug!(peer = %peer.ip(), %target, "tunnel opened");
            tunnel::pipe(&context, client, upstream).await;
        }
        Ok(Reached::Refused(response)) => tracing::warn!(
            peer = %peer.ip(),
            %target,
            status = response.status().as_u16(),
            "the parent proxy refused to open the tunnel"
        ),
        Err(failure) => tracing::warn!(
            peer = %peer.ip(),
            %target,
            reason = %failure.message(),
            "cannot open the tunnel"
        ),
    }
}
