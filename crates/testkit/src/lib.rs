//! Test support for gatir. Dev-only: never a dependency of the shipped binary.
//!
//! Mock origin servers and parent proxies (plain and NTLM). Later steps add
//! failing and slow ones, and injectable clock/nonce sources.

use std::net::SocketAddr;

pub mod fuzz;
pub mod http;
pub mod ntlm_origin;
pub mod ntlm_parent;
pub mod origin;
pub mod tcp;
pub mod tls;

/// A loopback address where nothing is listening: connecting is refused.
pub async fn closed_port() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    listener.local_addr().expect("local address")
}
