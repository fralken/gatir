//! Where the PAC script comes from and how it is kept up to date: fetched from
//! an address (with redirects, a size limit and a time limit), read again from
//! time to time, and never replaced by a version that does not work.

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use gatir::pac::{FetchError, Fetched, Trust, Validators, fetch};
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};

/// A server that names itself in every answer.
async fn named(name: &'static str) -> MockOrigin {
    MockOrigin::start(move |_| Reply::ok(name)).await
}

fn choosing(parent: SocketAddr) -> String {
    format!(r#"function FindProxyForURL(url, host) {{ return "PROXY {parent}"; }}"#)
}

async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> gatir_testkit::http::Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

/// What the parent named in the script answers, or the error page.
async fn through(proxy: &TestProxy) -> String {
    ask(proxy, get("site.test", "/", "")).await.body_text()
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("gave up waiting for {what}");
}

#[derive(Clone)]
enum Serve {
    Script(String),
    Status(u16),
}

/// Serves `/proxy.pac`, with an `ETag` and the answer to a comparison, and
/// changes what it serves on request.
struct PacServer {
    origin: MockOrigin,
    serve: Arc<Mutex<Serve>>,
    /// Complete answers, as opposed to `304`.
    full: Arc<AtomicUsize>,
}

impl PacServer {
    async fn start(first: Serve) -> Self {
        let serve = Arc::new(Mutex::new(first));
        let full = Arc::new(AtomicUsize::new(0));
        let origin = MockOrigin::start({
            let (serve, full) = (serve.clone(), full.clone());
            move |request| {
                let current = serve.lock().unwrap().clone();
                match current {
                    Serve::Status(code) => {
                        Reply::raw(format!("HTTP/1.1 {code} No\r\nContent-Length: 0\r\n\r\n"))
                    }
                    Serve::Script(script) => {
                        let etag = format!("\"{:x}\"", fnv(script.as_bytes()));
                        if request.headers.get("if-none-match") == Some(etag.as_str()) {
                            Reply::raw(format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\n\r\n"))
                        } else {
                            full.fetch_add(1, Ordering::SeqCst);
                            Reply::raw(format!(
                                "HTTP/1.1 200 OK\r\nETag: {etag}\r\n\
                                 Content-Type: application/x-ns-proxy-autoconfig\r\n\
                                 Content-Length: {}\r\n\r\n{script}",
                                script.len()
                            ))
                        }
                    }
                }
            }
        })
        .await;
        Self {
            origin,
            serve,
            full,
        }
    }

    fn set(&self, now: Serve) {
        *self.serve.lock().unwrap() = now;
    }

    fn url(&self) -> String {
        format!("http://{}/proxy.pac", self.origin.authority())
    }

    fn hits(&self) -> usize {
        self.origin.requests().len()
    }

    fn table(&self, extra: &str) -> String {
        format!("[pac]\nurl = {:?}\n{extra}", self.url())
    }
}

#[tokio::test]
async fn a_script_is_fetched_from_an_address_and_used() {
    let parent = named("A").await;
    let pac = PacServer::start(Serve::Script(choosing(parent.addr()))).await;
    let proxy = start_proxy(&pac.table("")).await;

    assert_eq!(through(&proxy).await, "A");

    let requests = pac.origin.requests();
    assert_eq!(requests.len(), 1, "one look at the start, none after");
    let request = &requests[0];
    assert_eq!(
        (request.method.as_str(), request.target.as_str()),
        ("GET", "/proxy.pac")
    );
    assert_eq!(
        request.headers.get("host"),
        Some(pac.origin.authority().as_str())
    );
    assert!(
        request
            .headers
            .get("user-agent")
            .unwrap()
            .starts_with("gatir/")
    );
    assert_eq!(request.headers.get("accept-encoding"), Some("identity"));
    assert!(!request.headers.contains("if-none-match"));
}

#[tokio::test]
async fn redirects_are_followed_across_servers() {
    let parent = named("A").await;
    let pac = PacServer::start(Serve::Script(choosing(parent.addr()))).await;
    let front = MockOrigin::start({
        let destination = pac.url();
        move |request| match request.target.as_str() {
            "/old" => {
                Reply::raw("HTTP/1.1 301 Moved\r\nLocation: middle\r\nContent-Length: 0\r\n\r\n")
            }
            "/middle" => Reply::raw(format!(
                "HTTP/1.1 307 Temporary\r\nLocation: {destination}\r\nContent-Length: 0\r\n\r\n"
            )),
            _ => Reply::raw("HTTP/1.1 404 No\r\nContent-Length: 0\r\n\r\n"),
        }
    })
    .await;
    let proxy = start_proxy(&format!(
        "[pac]\nurl = \"http://{}/old\"\n",
        front.authority()
    ))
    .await;

    assert_eq!(through(&proxy).await, "A");
    assert_eq!(front.requests().len(), 2);
}

#[tokio::test]
async fn a_redirect_loop_ends_in_an_error_that_says_so() {
    let front = MockOrigin::start(|_| {
        Reply::raw("HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n")
    })
    .await;
    let proxy = start_proxy(&format!(
        "[pac]\nurl = \"http://{}/p\"\n",
        front.authority()
    ))
    .await;

    // The first look and the five redirects it may follow.
    assert_eq!(front.requests().len(), 6);
    let response = ask(&proxy, get("site.test", "/", "")).await;
    assert_eq!(response.status, 502);
    let text = response.body_text();
    assert!(text.contains("more than 5 redirects"), "{text}");
    assert!(text.contains("keeps trying"), "{text}");
}

#[tokio::test]
async fn an_address_that_fails_at_the_start_is_retried_until_it_works() {
    let parent = named("A").await;
    let pac = PacServer::start(Serve::Status(503)).await;
    let proxy = start_proxy(&pac.table("refresh_secs = 1\n")).await;

    // gatir is up, and says what is wrong instead of going direct.
    let response = ask(&proxy, get("site.test", "/", "")).await;
    assert_eq!(response.status, 502);
    let text = response.body_text();
    assert!(text.contains("The PAC script could not tell"), "{text}");
    assert!(text.contains("503"), "{text}");

    pac.set(Serve::Script(choosing(parent.addr())));
    eventually("the script to be fetched", || async {
        through(&proxy).await == "A"
    })
    .await;
}

#[tokio::test]
async fn a_new_version_replaces_the_old_one() {
    let (a, b) = (named("A").await, named("B").await);
    let pac = PacServer::start(Serve::Script(choosing(a.addr()))).await;
    let mut proxy = start_proxy(&pac.table("refresh_secs = 1\n")).await;
    assert_eq!(through(&proxy).await, "A");

    pac.set(Serve::Script(choosing(b.addr())));
    eventually("the new script", || async { through(&proxy).await == "B" }).await;

    // The task that looks again ends with the server.
    proxy.shutdown.cancel();
    assert!(proxy.finished_within(Duration::from_secs(5)).await);
}

#[tokio::test]
async fn a_version_that_does_not_work_never_replaces_one_that_does() {
    let (a, b) = (named("A").await, named("B").await);
    let pac = PacServer::start(Serve::Script(choosing(a.addr()))).await;
    let proxy = start_proxy(&pac.table("refresh_secs = 1\n")).await;
    assert_eq!(through(&proxy).await, "A");

    for broken in [
        Serve::Script("function FindProxyForURL(url, host) { return ".to_owned()),
        Serve::Script("function NotTheOne() { return 'DIRECT'; }".to_owned()),
        Serve::Script(String::new()),
        Serve::Status(500),
        Serve::Status(404),
    ] {
        pac.set(broken);
        let before = pac.hits();
        eventually("a look at the broken version", || async {
            pac.hits() >= before + 2
        })
        .await;
        assert_eq!(through(&proxy).await, "A");
    }

    pac.set(Serve::Script(choosing(b.addr())));
    eventually("the version that works", || async {
        through(&proxy).await == "B"
    })
    .await;
}

#[tokio::test]
async fn a_script_that_has_not_changed_is_not_fetched_again() {
    let (a, b) = (named("A").await, named("B").await);
    let pac = PacServer::start(Serve::Script(choosing(a.addr()))).await;
    let proxy = start_proxy(&pac.table("refresh_secs = 1\n")).await;
    assert_eq!(through(&proxy).await, "A");

    eventually("three more looks", || async { pac.hits() >= 4 }).await;
    assert_eq!(pac.full.load(Ordering::SeqCst), 1, "a 304 is enough");
    assert_eq!(through(&proxy).await, "A");
    let requests = pac.origin.requests();
    let etag = format!("\"{:x}\"", fnv(choosing(a.addr()).as_bytes()));
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.headers.get("if-none-match") == Some(etag.as_str())),
        "every later look compares"
    );

    pac.set(Serve::Script(choosing(b.addr())));
    eventually("the new script", || async { through(&proxy).await == "B" }).await;
    assert_eq!(pac.full.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_slow_server_is_given_up_on() {
    let origin = MockOrigin::start(|_| Reply::ok("late").after(Duration::from_secs(5))).await;
    let started = Instant::now();
    let proxy = start_proxy(&format!(
        "[pac]\nurl = \"http://{}/p\"\nfetch_timeout_secs = 1\n",
        origin.authority()
    ))
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );

    let text = ask(&proxy, get("site.test", "/", "")).await.body_text();
    assert!(
        text.contains("no complete answer within 1 seconds"),
        "{text}"
    );
}

#[tokio::test]
async fn a_file_is_read_again_and_a_bad_version_is_ignored() {
    let (a, b) = (named("A").await, named("B").await);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy.pac");
    std::fs::write(&file, choosing(a.addr())).unwrap();
    let proxy = start_proxy(&format!(
        "[pac]\nfile = {:?}\nrefresh_secs = 1\n",
        file.display().to_string()
    ))
    .await;
    assert_eq!(through(&proxy).await, "A");

    std::fs::write(&file, choosing(b.addr())).unwrap();
    eventually("the edited file", || async { through(&proxy).await == "B" }).await;

    // Neither a script that does not compile nor a file that is gone
    // takes away the one in use.
    std::fs::write(&file, "function FindProxyForURL(").unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(through(&proxy).await, "B");
    std::fs::remove_file(&file).unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(through(&proxy).await, "B");

    std::fs::write(&file, choosing(a.addr())).unwrap();
    eventually("the file to come back", || async {
        through(&proxy).await == "A"
    })
    .await;
}

// ---- the fetch on its own ----

const LIMIT: Duration = Duration::from_secs(5);

async fn fetched(origin: &MockOrigin, path: &str) -> Result<Fetched, FetchError> {
    fetch(
        &format!("http://{}{path}", origin.authority()),
        LIMIT,
        &Validators::default(),
        &Trust::system(),
    )
    .await
}

#[tokio::test]
async fn a_script_over_the_size_limit_is_refused_however_it_is_sent() {
    const LIMIT_BYTES: usize = 16 * 1024 * 1024;
    let origin = MockOrigin::start(|request| match request.target.as_str() {
        "/exact" => Reply::ok(&"a".repeat(LIMIT_BYTES)),
        "/announced" => Reply::ok(&"a".repeat(LIMIT_BYTES + 1)),
        // Refused on the announcement: the rest of it never comes.
        "/huge" => Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\n\r\nabc"),
        _ => {
            let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for _ in 0..=LIMIT_BYTES / (1024 * 1024) {
                response.extend_from_slice(b"100000\r\n");
                response.extend(std::iter::repeat_n(b'a', 1024 * 1024));
                response.extend_from_slice(b"\r\n");
            }
            response.extend_from_slice(b"0\r\n\r\n");
            Reply::raw(response)
        }
    })
    .await;

    match fetched(&origin, "/exact").await {
        Ok(Fetched::Script { bytes, .. }) => assert_eq!(bytes.len(), LIMIT_BYTES),
        other => panic!("a script of the largest size allowed: {other:?}"),
    }
    for path in ["/announced", "/huge", "/chunked"] {
        assert!(
            matches!(fetched(&origin, path).await, Err(FetchError::TooLarge)),
            "{path}"
        );
    }
}

#[tokio::test]
async fn what_the_server_gets_wrong_is_reported_not_guessed() {
    let origin = MockOrigin::start(|request| {
        let head = |status: &str, more: &str| {
            Reply::raw(format!(
                "HTTP/1.1 {status}\r\n{more}Content-Length: 0\r\n\r\n"
            ))
        };
        match request.target.as_str() {
            "/gzip" => Reply::raw(
                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc",
            ),
            "/no-comparison" => head("304 Not Modified", ""),
            "/no-location" => head("302 Found", ""),
            "/ftp" => head("302 Found", "Location: ftp://h.example.com/p.pac\r\n"),
            "/credentials" => head("302 Found", "Location: http://user:pw@h.example.com/\r\n"),
            "/gone" => head("410 Gone", ""),
            "/cut" => {
                Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort").then_close()
            }
            _ => head("500 Oops", ""),
        }
    })
    .await;

    assert!(matches!(
        fetched(&origin, "/gzip").await,
        Err(FetchError::Encoded(_))
    ));
    assert!(matches!(
        fetched(&origin, "/no-comparison").await,
        Err(FetchError::Unexpected(_))
    ));
    for path in ["/no-location", "/cut"] {
        assert!(
            matches!(fetched(&origin, path).await, Err(FetchError::Protocol(_))),
            "{path}"
        );
    }
    for path in ["/ftp", "/credentials"] {
        assert!(
            matches!(
                fetched(&origin, path).await,
                Err(FetchError::BadRedirect(_))
            ),
            "{path}"
        );
    }
    assert!(matches!(
        fetched(&origin, "/gone").await,
        Err(FetchError::Status(status)) if status.as_u16() == 410
    ));
}

#[tokio::test]
async fn an_address_nobody_listens_on_and_one_that_never_answers_are_errors() {
    let closed = gatir_testkit::closed_port().await;
    let error = fetch(
        &format!("http://{closed}/p"),
        LIMIT,
        &Validators::default(),
        &Trust::system(),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, FetchError::Connect { .. }), "{error}");

    let silent = MockOrigin::start(|_| Reply::ok("late").after(Duration::from_secs(10))).await;
    let error = fetch(
        &format!("http://{}/p", silent.authority()),
        Duration::from_millis(300),
        &Validators::default(),
        &Trust::system(),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, FetchError::Timeout(_)), "{error}");
}
