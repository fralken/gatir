//! Fetching a PAC script from an `http://` or `https://` address.
//!
//! One `GET` on a connection of its own, with a limit on the whole exchange, on
//! the size of the script and on the redirects followed. A script that has not
//! changed is recognized by the validators the server sent last time
//! (RFC 9110, 13.1), so that the server can answer `304` instead of sending it
//! again.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Incoming};
use hyper::header::{
    ACCEPT, ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, ETAG, HOST, HeaderMap,
    IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, USER_AGENT,
};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_native_tls::{TlsConnector, native_tls};

use super::MAX_SCRIPT_BYTES;

/// Redirects followed before giving up.
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("cannot connect to {address}: {source}")]
    Connect {
        address: String,
        source: std::io::Error,
    },
    #[error("no complete answer within {} seconds", .0.as_secs())]
    Timeout(Duration),
    #[error("the server answered {0}")]
    Status(StatusCode),
    #[error("the script is larger than the {MAX_SCRIPT_BYTES} bytes allowed")]
    TooLarge,
    #[error("more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects,
    #[error("cannot follow a redirect to \"{0}\"")]
    BadRedirect(String),
    #[error("the server sent the script encoded as \"{0}\", and gatir asked for it as it is")]
    Encoded(String),
    #[error("the server answered {0} to a request that asked for no comparison")]
    Unexpected(StatusCode),
    #[error("invalid answer from the server: {0}")]
    Protocol(String),
    #[error("refusing a redirect from https to http: \"{0}\"")]
    Downgrade(String),
    #[error(
        "TLS with {host} failed: {reason} (its certificate must be valid for that name and \
         issued by an authority this system trusts)"
    )]
    Tls { host: String, reason: String },
}

fn protocol(error: hyper::Error) -> FetchError {
    FetchError::Protocol(error.to_string())
}

/// Which certificate authorities are trusted for an `https://` address: the
/// ones the operating system trusts, so that a corporate authority installed
/// there works without further configuration.
#[derive(Debug, Clone, Default)]
pub struct Trust {
    extra_root: Option<Vec<u8>>,
}

impl Trust {
    pub fn system() -> Self {
        Self::default()
    }

    /// The system's authorities and one more, given as PEM. For tests, which
    /// run an authority of their own.
    pub fn system_and(root_pem: &[u8]) -> Self {
        Self {
            extra_root: Some(root_pem.to_vec()),
        }
    }

    fn connector(&self, host: &str) -> Result<TlsConnector, FetchError> {
        let failed = |reason: String| FetchError::Tls {
            host: host.to_owned(),
            reason,
        };
        let mut builder = native_tls::TlsConnector::builder();
        if let Some(pem) = &self.extra_root {
            let root =
                native_tls::Certificate::from_pem(pem).map_err(|err| failed(err.to_string()))?;
            builder.add_root_certificate(root);
        }
        builder
            .build()
            .map(TlsConnector::from)
            .map_err(|err| failed(err.to_string()))
    }
}

/// What the server said identifies the version of the script it sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    etag: Option<String>,
    last_modified: Option<String>,
}

impl Validators {
    fn from_headers(headers: &HeaderMap) -> Self {
        let text = |name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        Self {
            etag: text(ETAG),
            last_modified: text(LAST_MODIFIED),
        }
    }
}

#[derive(Debug)]
pub enum Fetched {
    Script {
        bytes: Vec<u8>,
        validators: Validators,
    },
    /// The server confirmed that the script `known` describes is still current.
    Unchanged,
}

enum Step {
    Done(Fetched),
    Redirect(String),
}

/// Fetches the script at `address`, giving up after `limit` for everything
/// together. `known` says which version is held, to ask for a newer one only.
pub async fn fetch(
    address: &str,
    limit: Duration,
    known: &Validators,
    trust: &Trust,
) -> Result<Fetched, FetchError> {
    let follow = async {
        let mut uri = check(address.parse().map_err(|_| bad_redirect(address))?, address)?;
        for _ in 0..=MAX_REDIRECTS {
            match get(&uri, known, trust).await? {
                Step::Done(fetched) => return Ok(fetched),
                Step::Redirect(location) => {
                    let next = resolve(&uri, &location)?;
                    // Nothing that was fetched securely may be sent on in the clear.
                    if uri.scheme_str() == Some("https") && next.scheme_str() != Some("https") {
                        return Err(FetchError::Downgrade(bad_redirect_text(&location)));
                    }
                    uri = next;
                }
            }
        }
        Err(FetchError::TooManyRedirects)
    };
    tokio::time::timeout(limit, follow)
        .await
        .map_err(|_| FetchError::Timeout(limit))?
}

fn bad_redirect(location: &str) -> FetchError {
    FetchError::BadRedirect(bad_redirect_text(location))
}

/// A query may hold a token, and the log is not a place for it.
fn bad_redirect_text(location: &str) -> String {
    location
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// An address gatir may connect to: http or https, a host, no credentials.
fn check(uri: Uri, original: &str) -> Result<Uri, FetchError> {
    let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
    let authority_ok = uri
        .authority()
        .is_some_and(|authority| !authority.host().is_empty() && !authority.as_str().contains('@'));
    if scheme_ok && authority_ok {
        Ok(uri)
    } else {
        Err(bad_redirect(original))
    }
}

async fn get(uri: &Uri, known: &Validators, trust: &Trust) -> Result<Step, FetchError> {
    let https = uri.scheme_str() == Some("https");
    let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let address = format!("{host}:{port}");
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|source| FetchError::Connect { address, source })?;
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(%err, "cannot set TCP_NODELAY on the PAC connection");
    }
    if https {
        // The name is what the certificate is checked against, and what the
        // server is told it is talking to (for an address, no name is sent).
        let secured = trust
            .connector(host)?
            .connect(host, stream)
            .await
            .map_err(|err| FetchError::Tls {
                host: host.to_owned(),
                reason: err.to_string(),
            })?;
        exchange(secured, request(uri, known)).await
    } else {
        exchange(stream, request(uri, known)).await
    }
}

fn request(uri: &Uri, known: &Validators) -> Request<Empty<Bytes>> {
    let target = uri.path_and_query().map_or("/", |target| target.as_str());
    let authority = uri.authority().map_or("", |authority| authority.as_str());
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(target)
        .header(HOST, authority)
        .header(USER_AGENT, concat!("gatir/", env!("CARGO_PKG_VERSION")))
        .header(ACCEPT, "*/*")
        // The script is read as it comes: decompressing is not worth a codec.
        .header(ACCEPT_ENCODING, "identity")
        .header(CONNECTION, "close");
    if let Some(etag) = &known.etag {
        request = request.header(IF_NONE_MATCH, etag);
    }
    if let Some(date) = &known.last_modified {
        request = request.header(IF_MODIFIED_SINCE, date);
    }
    request
        .body(Empty::new())
        .expect("a request built from a checked address")
}

/// Stops the task that drives a connection when the exchange is over.
struct Driver(JoinHandle<Result<(), hyper::Error>>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn exchange<T>(io: T, request: Request<Empty<Bytes>>) -> Result<Step, FetchError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conditional = request.headers().contains_key(IF_NONE_MATCH)
        || request.headers().contains_key(IF_MODIFIED_SINCE);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(protocol)?;
    let _driver = Driver(tokio::spawn(connection));
    let response = sender.send_request(request).await.map_err(protocol)?;
    classify(response, conditional).await
}

async fn classify(response: Response<Incoming>, conditional: bool) -> Result<Step, FetchError> {
    let status = response.status();
    match status {
        StatusCode::OK => {
            let encoding = response
                .headers()
                .get(CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|encoding| {
                    !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity")
                });
            if let Some(encoding) = encoding {
                return Err(FetchError::Encoded(encoding.to_owned()));
            }
            let validators = Validators::from_headers(response.headers());
            let bytes = read_capped(response.into_body()).await?;
            Ok(Step::Done(Fetched::Script { bytes, validators }))
        }
        StatusCode::NOT_MODIFIED if conditional => Ok(Step::Done(Fetched::Unchanged)),
        StatusCode::NOT_MODIFIED => Err(FetchError::Unexpected(status)),
        StatusCode::MOVED_PERMANENTLY
        | StatusCode::FOUND
        | StatusCode::SEE_OTHER
        | StatusCode::TEMPORARY_REDIRECT
        | StatusCode::PERMANENT_REDIRECT => {
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| FetchError::Protocol("a redirect without a Location".to_owned()))?;
            Ok(Step::Redirect(location.to_owned()))
        }
        other => Err(FetchError::Status(other)),
    }
}

async fn read_capped(mut body: Incoming) -> Result<Vec<u8>, FetchError> {
    // A length that is announced is checked before anything is read.
    if body.size_hint().lower() > MAX_SCRIPT_BYTES as u64 {
        return Err(FetchError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(protocol)?;
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() > MAX_SCRIPT_BYTES {
                return Err(FetchError::TooLarge);
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}

/// The address a `Location` field points to, as seen from `base`
/// (RFC 3986, 5.2).
fn resolve(base: &Uri, location: &str) -> Result<Uri, FetchError> {
    let location = location.trim();
    let scheme = base.scheme_str().unwrap_or("http");
    let authority = base.authority().map_or("", |authority| authority.as_str());
    let first_part = location.split(['/', '?', '#']).next().unwrap_or_default();

    let absolute = if location.is_empty() {
        return Err(bad_redirect(location));
    } else if let Some(rest) = location.strip_prefix("//") {
        format!("{scheme}://{rest}")
    } else if first_part.contains(':') {
        location.to_owned()
    } else {
        let (path, tail) = match location.find(['?', '#']) {
            Some(at) => location.split_at(at),
            None => (location, ""),
        };
        let path = if path.is_empty() {
            base.path().to_owned()
        } else if path.starts_with('/') {
            without_dot_segments(path)
        } else {
            let directory = &base.path()[..=base.path().rfind('/').unwrap_or(0)];
            without_dot_segments(&format!("{directory}{path}"))
        };
        format!("{scheme}://{authority}{path}{tail}")
    };
    // A fragment is for the client and is not sent.
    let absolute = absolute.split('#').next().unwrap_or_default();
    check(
        absolute.parse().map_err(|_| bad_redirect(location))?,
        location,
    )
}

/// RFC 3986, 5.2.4.
fn without_dot_segments(path: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        match *segment {
            "." => {
                if last {
                    kept.push("");
                }
            }
            ".." => {
                if kept.len() > 1 {
                    kept.pop();
                }
                if last {
                    kept.push("");
                }
            }
            other => kept.push(other),
        }
    }
    kept.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(base: &str, location: &str) -> String {
        resolve(&base.parse().unwrap(), location)
            .unwrap()
            .to_string()
    }

    #[test]
    fn a_location_is_resolved_against_the_address_it_came_from() {
        let base = "http://pac.example.com:8080/a/b/proxy.pac?x=1";
        for (location, expected) in [
            (
                "https://other.example.com/p.pac",
                "https://other.example.com/p.pac",
            ),
            ("//cdn.example.com/p.pac", "http://cdn.example.com/p.pac"),
            ("/root.pac", "http://pac.example.com:8080/root.pac"),
            ("next.pac", "http://pac.example.com:8080/a/b/next.pac"),
            ("../up.pac", "http://pac.example.com:8080/a/up.pac"),
            (
                "../../../way/up.pac",
                "http://pac.example.com:8080/way/up.pac",
            ),
            (
                "./same.pac?y=2",
                "http://pac.example.com:8080/a/b/same.pac?y=2",
            ),
            ("?y=3", "http://pac.example.com:8080/a/b/proxy.pac?y=3"),
            ("/moved.pac#top", "http://pac.example.com:8080/moved.pac"),
            ("../", "http://pac.example.com:8080/a/"),
        ] {
            assert_eq!(resolved(base, location), expected, "{location}");
        }
    }

    #[test]
    fn a_location_that_leads_nowhere_usable_is_refused() {
        let base: Uri = "https://pac.example.com/p.pac".parse().unwrap();
        for location in [
            "",
            "ftp://pac.example.com/p.pac",
            "file:///etc/passwd",
            "http://user:pw@pac.example.com/p.pac",
            "javascript:alert(1)",
            "http://",
        ] {
            assert!(resolve(&base, location).is_err(), "{location:?}");
        }
    }

    #[test]
    fn an_error_never_shows_the_query_of_an_address() {
        let error = bad_redirect("https://h.example.com/p.pac?token=hush").to_string();
        assert!(error.contains("https://h.example.com/p.pac"), "{error}");
        assert!(!error.contains("hush"), "{error}");
    }

    #[test]
    fn validators_are_what_the_server_names() {
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, "\"v1\"".parse().unwrap());
        headers.insert(
            LAST_MODIFIED,
            "Tue, 01 Jan 2030 00:00:00 GMT".parse().unwrap(),
        );
        let validators = Validators::from_headers(&headers);
        assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
        assert_eq!(
            validators.last_modified.as_deref(),
            Some("Tue, 01 Jan 2030 00:00:00 GMT")
        );
        assert_eq!(
            Validators::from_headers(&HeaderMap::new()),
            Validators::default()
        );
    }
}
