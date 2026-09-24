//! Test support for gatir. Dev-only: never a dependency of the shipped binary.
//!
//! Later steps add mock parent proxies (plain, NTLM, failing, slow) and
//! injectable clock/nonce sources here.

use std::net::SocketAddr;

pub mod http;
pub mod origin;

/// A loopback address where nothing is listening: connecting is refused.
pub async fn closed_port() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    listener.local_addr().expect("local address")
}
