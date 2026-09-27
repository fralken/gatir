//! A SOCKS5 server (RFC 1928, with the user name and password method of
//! RFC 1929). It does one thing: CONNECT. The client names a destination, and
//! once the way there is open, the connection is a pipe to it, like a tunnel.
//!
//! Every read is of a length that is known before it starts, and nothing is
//! read ahead, so a client that sends its first bytes without waiting for the
//! reply loses none of them, and one that sends a byte at a time is served.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use hyper::StatusCode;
use hyper::header::HeaderMap;
use hyper::http::Extensions;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::failure::Failure;
use super::server::Context;
use super::tunnel::{self, Reached};
use crate::config::Socks5Credentials;

const VERSION: u8 = 5;
/// The version of the user name and password sub-negotiation (RFC 1929).
const AUTH_VERSION: u8 = 1;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;

const COMMAND_CONNECT: u8 = 0x01;

const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x03;
const ADDRESS_IPV6: u8 = 0x04;

const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_NOT_ALLOWED: u8 = 0x02;
const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_TTL_EXPIRED: u8 = 0x06;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// What a client asked to be connected to.
#[derive(Debug, PartialEq, Eq)]
struct Destination {
    /// As it appears in a URL: an IPv6 address is in brackets.
    host: String,
    port: u16,
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Why a client got no further than the handshake.
#[derive(Debug)]
enum Stop {
    /// The connection is dropped without another word.
    Silent(&'static str),
    /// The client gave a wrong user name or password.
    NotAuthenticated,
    /// The request is answered with this code, and the connection closed.
    Reply(u8, &'static str),
    Io(io::Error),
}

impl From<io::Error> for Stop {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

async fn read_array<S, const N: usize>(stream: &mut S) -> io::Result<[u8; N]>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = [0u8; N];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// Agrees on how the client proves who it is, and checks it.
///
/// With credentials configured the only method accepted is user name and
/// password; without, it is none. A client that offers nothing acceptable is
/// told so, as RFC 1928 says, and dropped.
async fn negotiate<S>(stream: &mut S, credentials: Option<&Socks5Credentials>) -> Result<(), Stop>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let [version, count] = read_array(stream).await?;
    if version != VERSION {
        return Err(Stop::Silent("the client does not speak SOCKS5"));
    }
    let mut offered = vec![0u8; usize::from(count)];
    stream.read_exact(&mut offered).await?;

    let wanted = if credentials.is_some() {
        METHOD_PASSWORD
    } else {
        METHOD_NO_AUTH
    };
    if !offered.contains(&wanted) {
        stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await?;
        return Err(Stop::Silent(
            "the client offers no way of authenticating that gatir accepts",
        ));
    }
    stream.write_all(&[VERSION, wanted]).await?;

    let Some(credentials) = credentials else {
        return Ok(());
    };
    let [version, user_len] = read_array(stream).await?;
    if version != AUTH_VERSION {
        return Err(Stop::Silent("a wrong version of the authentication"));
    }
    let mut username = Zeroizing::new(vec![0u8; usize::from(user_len)]);
    stream.read_exact(&mut username).await?;
    let [password_len] = read_array(stream).await?;
    let mut password = Zeroizing::new(vec![0u8; usize::from(password_len)]);
    stream.read_exact(&mut password).await?;

    // An empty field cannot be right: the configuration does not allow one.
    let accepted =
        !username.is_empty() && !password.is_empty() && credentials.verify(&username, &password);
    stream
        .write_all(&[AUTH_VERSION, u8::from(!accepted)])
        .await?;
    if accepted {
        Ok(())
    } else {
        Err(Stop::NotAuthenticated)
    }
}

/// A host name as a client may send it: letters, digits, dots, hyphens and
/// underscores. Anything else could not be looked up, and would not survive
/// being put in a CONNECT request.
fn host_name(bytes: &[u8]) -> Option<String> {
    let valid = !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    valid.then(|| String::from_utf8_lossy(bytes).into_owned())
}

async fn read_request<S>(stream: &mut S) -> Result<Destination, Stop>
where
    S: AsyncRead + Unpin,
{
    let [version, command, _reserved, address_type] = read_array(stream).await?;
    if version != VERSION {
        return Err(Stop::Silent("a request that is not SOCKS5"));
    }
    if command != COMMAND_CONNECT {
        return Err(Stop::Reply(
            REPLY_COMMAND_NOT_SUPPORTED,
            "only CONNECT is supported",
        ));
    }
    let host = match address_type {
        ADDRESS_IPV4 => Ipv4Addr::from(read_array::<_, 4>(stream).await?).to_string(),
        ADDRESS_IPV6 => format!("[{}]", Ipv6Addr::from(read_array::<_, 16>(stream).await?)),
        ADDRESS_DOMAIN => {
            let [length] = read_array(stream).await?;
            let mut name = vec![0u8; usize::from(length)];
            stream.read_exact(&mut name).await?;
            host_name(&name).ok_or(Stop::Reply(
                REPLY_HOST_UNREACHABLE,
                "the host name is empty or has characters no host name has",
            ))?
        }
        _ => {
            return Err(Stop::Reply(
                REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
                "an unknown type of address",
            ));
        }
    };
    let port = u16::from_be_bytes(read_array(stream).await?);
    if port == 0 {
        return Err(Stop::Reply(REPLY_NOT_ALLOWED, "port 0 is no destination"));
    }
    Ok(Destination { host, port })
}

async fn handshake<S>(
    stream: &mut S,
    credentials: Option<&Socks5Credentials>,
) -> Result<Destination, Stop>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate(stream, credentials).await?;
    read_request(stream).await
}

/// Answers a request. `bound` is where the connection to the destination
/// starts, from the destination's side; a failure has none.
async fn send_reply<S>(stream: &mut S, code: u8, bound: SocketAddr) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = Vec::with_capacity(22);
    reply.extend_from_slice(&[VERSION, code, 0]);
    match bound.ip() {
        IpAddr::V4(address) => {
            reply.push(ADDRESS_IPV4);
            reply.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            reply.push(ADDRESS_IPV6);
            reply.extend_from_slice(&address.octets());
        }
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&reply).await?;
    stream.flush().await
}

const NO_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// The code that tells a client best why the destination could not be reached.
fn reply_for(failure: &Failure) -> u8 {
    match failure {
        Failure::ConnectTimeout(_) | Failure::ResponseTimeout(_) => REPLY_TTL_EXPIRED,
        Failure::Connect { source, .. } => match source.kind() {
            io::ErrorKind::ConnectionRefused => REPLY_CONNECTION_REFUSED,
            io::ErrorKind::NetworkUnreachable => REPLY_NETWORK_UNREACHABLE,
            _ => REPLY_HOST_UNREACHABLE,
        },
        Failure::ParentsUnavailable(_) => REPLY_NETWORK_UNREACHABLE,
        // What went wrong is in the log: SOCKS5 has no place for the words.
        _ => REPLY_GENERAL_FAILURE,
    }
}

/// The same, for a parent proxy that refused to open a tunnel.
fn reply_for_status(status: StatusCode) -> u8 {
    match status {
        StatusCode::FORBIDDEN => REPLY_NOT_ALLOWED,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => REPLY_HOST_UNREACHABLE,
        StatusCode::GATEWAY_TIMEOUT => REPLY_TTL_EXPIRED,
        _ => REPLY_GENERAL_FAILURE,
    }
}

/// Serves one SOCKS5 client until its tunnel is closed.
pub(super) async fn serve(mut client: TcpStream, peer: SocketAddr, context: Arc<Context>) {
    // The settings as they are when the client arrives: a reload during its
    // handshake does not change what it is asked for.
    let live = context.live();
    if let Err(err) = client.set_nodelay(true) {
        tracing::debug!(%peer, %err, "cannot set TCP_NODELAY on the client connection");
    }
    let peer_ip = peer.ip();

    // A client gets as long to say what it wants as an HTTP client gets to
    // send its request.
    let handshake = timeout(
        live.timeouts.client_idle,
        handshake(&mut client, live.socks5_credentials.as_deref()),
    )
    .await;
    let destination = match handshake {
        Ok(Ok(destination)) => destination,
        Ok(Err(Stop::Reply(code, reason))) => {
            tracing::debug!(peer = %peer_ip, reason, "SOCKS5 request refused");
            let _ = send_reply(&mut client, code, NO_ADDRESS).await;
            let _ = client.shutdown().await;
            return;
        }
        Ok(Err(Stop::NotAuthenticated)) => {
            tracing::warn!(peer = %peer_ip, "SOCKS5 client gave a wrong user name or password");
            return;
        }
        Ok(Err(Stop::Silent(reason))) => {
            tracing::debug!(peer = %peer_ip, reason, "SOCKS5 client dropped");
            return;
        }
        Ok(Err(Stop::Io(err))) => {
            tracing::debug!(peer = %peer_ip, %err, "SOCKS5 handshake ended with an error");
            return;
        }
        Err(_) => {
            tracing::debug!(peer = %peer_ip, "the SOCKS5 handshake took too long");
            return;
        }
    };

    let reached = tunnel::reach(
        &context,
        &destination.host,
        destination.port,
        HeaderMap::new(),
        Extensions::new(),
    )
    .await;
    let code = match reached {
        Ok(Reached::Open(upstream)) => {
            let bound = upstream.local_addr().unwrap_or(NO_ADDRESS);
            if send_reply(&mut client, REPLY_SUCCEEDED, bound)
                .await
                .is_err()
            {
                return;
            }
            tracing::debug!(peer = %peer_ip, %destination, "SOCKS5 tunnel opened");
            tunnel::pipe(&context, client, upstream).await;
            return;
        }
        Ok(Reached::Refused(response)) => {
            tracing::warn!(
                peer = %peer_ip,
                %destination,
                status = response.status().as_u16(),
                "the parent proxy refused to open the tunnel"
            );
            reply_for_status(response.status())
        }
        Err(failure) => {
            tracing::warn!(
                peer = %peer_ip,
                %destination,
                reason = %failure.message(),
                "cannot open the SOCKS5 tunnel"
            );
            reply_for(&failure)
        }
    };
    let _ = send_reply(&mut client, code, NO_ADDRESS).await;
    let _ = client.shutdown().await;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use gatir_testkit::fuzz::each_variant;

    use super::*;

    /// Runs the handshake against what a client sends, and says what came of it.
    fn handshake_with(
        runtime: &tokio::runtime::Runtime,
        input: &[u8],
        credentials: Option<&Socks5Credentials>,
    ) -> Result<Destination, Stop> {
        runtime.block_on(async {
            let (mut client, mut server) = tokio::io::duplex(8 * 1024);
            client.write_all(input).await.unwrap();
            // The client says no more, and stays to hear the replies.
            client.shutdown().await.unwrap();
            let done = timeout(Duration::from_secs(2), handshake(&mut server, credentials)).await;
            drop(client);
            done.expect("the handshake ended, for want of more from the client")
        })
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

    fn bob() -> Socks5Credentials {
        let config = crate::config::Config::from_toml_str(
            "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = \"s3cret\"\n",
            crate::config::Overrides::default(),
        )
        .unwrap();
        config.socks5.unwrap().credentials.unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// What a destination must be for the CONNECT request that is made of it.
    fn assert_safe(destination: &Destination) {
        assert_ne!(destination.port, 0);
        assert!(!destination.host.is_empty());
        assert!(
            destination
                .host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_:[]".contains(&byte)),
            "{destination}"
        );
    }

    #[test]
    fn fuzz_a_socks5_request_without_authentication() {
        let runtime = runtime();
        // Methods offered, then CONNECT to a name, to an IPv4 and to an IPv6 address.
        let mut domain = vec![5, 1, 0, 5, 1, 0, 3, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&443u16.to_be_bytes());
        let ipv4 = [5, 2, 0, 2, 5, 1, 0, 1, 192, 0, 2, 1, 0, 80];
        let mut ipv6 = vec![5, 1, 0, 5, 1, 0, 4];
        ipv6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ipv6.extend_from_slice(&8080u16.to_be_bytes());

        let wanted = handshake_with(&runtime, &domain, None).expect("the seed is a request");
        assert_eq!(
            wanted,
            Destination {
                host: "example.com".into(),
                port: 443
            }
        );
        each_variant(&[&domain, &ipv4, &ipv6], 5_000, |input| {
            if let Ok(destination) = handshake_with(&runtime, input, None) {
                assert_safe(&destination);
            }
        });
    }

    #[test]
    fn fuzz_a_socks5_request_with_a_user_name_and_password() {
        let runtime = runtime();
        let bob = bob();
        // Methods (user name and password), then the pair, then CONNECT to a name.
        let mut seed = vec![5, 1, 2, 1, 3];
        seed.extend_from_slice(b"bob");
        seed.push(6);
        seed.extend_from_slice(b"s3cret");
        seed.extend_from_slice(&[5, 1, 0, 3, 11]);
        seed.extend_from_slice(b"example.com");
        seed.extend_from_slice(&443u16.to_be_bytes());

        handshake_with(&runtime, &seed, Some(&bob)).expect("the seed is a request");
        each_variant(&[&seed], 8_000, |input| {
            if let Ok(destination) = handshake_with(&runtime, input, Some(&bob)) {
                assert_safe(&destination);
                // Nobody gets in without the pair, whatever else is changed.
                assert!(
                    contains(input, b"bob") && contains(input, b"s3cret"),
                    "let in without the user name and password"
                );
            }
        });
    }

    #[test]
    fn a_host_name_is_letters_digits_dots_hyphens_and_underscores() {
        for name in [
            "example.com",
            "a",
            "my_host-1.corp",
            "127.0.0.1",
            "XN--bcher-kva.example",
        ] {
            assert_eq!(host_name(name.as_bytes()).as_deref(), Some(name), "{name}");
        }
        for name in [
            &b""[..],
            b"has space.com",
            b"tab\t.com",
            b"new\nline",
            b"a/b",
            b"user@host",
            b"host:80",
            b"[::1]",
            b"caf\xc3\xa9.example",
            b"nul\0byte",
            b"a\r\nHost: evil",
        ] {
            assert_eq!(host_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn a_failure_is_told_to_the_client_as_the_nearest_code() {
        let refused = Failure::Connect {
            address: "x:1".into(),
            source: io::ErrorKind::ConnectionRefused.into(),
        };
        assert_eq!(reply_for(&refused), REPLY_CONNECTION_REFUSED);
        let unreachable = Failure::Connect {
            address: "x:1".into(),
            source: io::ErrorKind::NetworkUnreachable.into(),
        };
        assert_eq!(reply_for(&unreachable), REPLY_NETWORK_UNREACHABLE);
        let unresolved = Failure::Connect {
            address: "x:1".into(),
            source: io::Error::other("failed to lookup address information"),
        };
        assert_eq!(reply_for(&unresolved), REPLY_HOST_UNREACHABLE);
        assert_eq!(
            reply_for(&Failure::ConnectTimeout("x:1".into())),
            REPLY_TTL_EXPIRED
        );
        assert_eq!(
            reply_for(&Failure::ResponseTimeout("the parent proxy")),
            REPLY_TTL_EXPIRED
        );
        assert_eq!(
            reply_for(&Failure::ParentsUnavailable(Vec::new())),
            REPLY_NETWORK_UNREACHABLE
        );
        assert_eq!(
            reply_for(&Failure::CoolingDown(std::time::Duration::from_secs(1))),
            REPLY_GENERAL_FAILURE
        );
    }

    #[test]
    fn a_parent_that_refuses_is_told_to_the_client_as_the_nearest_code() {
        for (status, code) in [
            (StatusCode::FORBIDDEN, REPLY_NOT_ALLOWED),
            (StatusCode::BAD_GATEWAY, REPLY_HOST_UNREACHABLE),
            (StatusCode::SERVICE_UNAVAILABLE, REPLY_HOST_UNREACHABLE),
            (StatusCode::GATEWAY_TIMEOUT, REPLY_TTL_EXPIRED),
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                REPLY_GENERAL_FAILURE,
            ),
            (StatusCode::NOT_FOUND, REPLY_GENERAL_FAILURE),
        ] {
            assert_eq!(reply_for_status(status), code, "{status}");
        }
    }

    #[tokio::test]
    async fn a_reply_carries_the_address_it_was_given() {
        let mut out = Vec::new();
        send_reply(&mut out, REPLY_SUCCEEDED, "10.1.2.3:8080".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(out, [5, 0, 0, 1, 10, 1, 2, 3, 0x1f, 0x90]);

        let mut out = Vec::new();
        send_reply(
            &mut out,
            REPLY_HOST_UNREACHABLE,
            "[::1]:443".parse().unwrap(),
        )
        .await
        .unwrap();
        let mut expected = vec![5, 4, 0, 4];
        expected.extend_from_slice(&[0; 15]);
        expected.extend_from_slice(&[1, 0x01, 0xbb]);
        assert_eq!(out, expected);

        let mut out = Vec::new();
        send_reply(&mut out, REPLY_GENERAL_FAILURE, NO_ADDRESS)
            .await
            .unwrap();
        assert_eq!(out, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
}
