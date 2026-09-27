//! `gatir-loadgen`: two small tools for load-testing an HTTP proxy, gatir or
//! any other. See `docs/load-testing.md` for why these exist instead of
//! curl/ab/wrk, and how to use them.
//!
//! - `serve-parent` stands up a real, NTLM-challenging parent proxy to point
//!   the proxy under test at, so a load run exercises real authentication
//!   instead of a bare, no-auth-needed backend.
//! - `bench` opens a number of persistent HTTP/1.1 connections through the
//!   proxy under test and fires sequential keep-alive `GET`s on each for a
//!   fixed duration, reporting throughput and latency percentiles.

use std::env;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::Reply;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper::header::HOST;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("cannot start the async runtime");
    match args.next().as_deref() {
        Some("serve-parent") => runtime.block_on(serve_parent(args)),
        Some("bench") => runtime.block_on(bench(args)),
        _ => {
            eprintln!(
                "usage:\n\
                 \x20 gatir-loadgen serve-parent [--user U] [--domain D] [--password P]\n\
                 \x20 gatir-loadgen bench <proxy-host:port> <origin-host:port> <connections> <seconds>"
            );
            ExitCode::from(2)
        }
    }
}

/// A real NTLM-challenging parent, so the proxy under test authenticates a
/// connection the way it would against a real corporate proxy, instead of
/// forwarding to a backend that never asks for anything. Prints the address
/// it bound to (an ephemeral port) and the identity to configure, then serves
/// until interrupted.
async fn serve_parent(mut args: impl Iterator<Item = String>) -> ExitCode {
    let (mut user, mut domain, mut password) = (
        "bench".to_owned(),
        "BENCH".to_owned(),
        "change-me".to_owned(),
    );
    while let Some(flag) = args.next() {
        let Some(value) = args.next() else {
            eprintln!("{flag} needs a value");
            return ExitCode::from(2);
        };
        match flag.as_str() {
            "--user" => user = value,
            "--domain" => domain = value,
            "--password" => password = value,
            other => {
                eprintln!("unknown option: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let body = "x".repeat(512);
    // An explicit `Connection: keep-alive`, not just the absence of `close`:
    // some proxies only treat a connection as reusable when the party on the
    // other end says so outright, RFC 9110's HTTP/1.1-is-persistent-by-default
    // notwithstanding. Answering this way, like a real corporate proxy would,
    // is what makes this a fair partner to benchmark against.
    let raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
        body.len(),
        body
    );
    let parent = MockNtlmParent::start(
        Account::new(&user, &domain, &password),
        Options::default(),
        move |_request| Reply::raw(raw.clone()),
    )
    .await;
    println!("listening on {}", parent.addr());
    println!("credentials: user={user} domain={domain} password={password}");
    println!("(Ctrl-C to stop)");

    let _ = tokio::signal::ctrl_c().await;
    ExitCode::SUCCESS
}

/// Opens `connections` persistent HTTP/1.1 connections through `proxy` and
/// fires sequential `GET`s for `origin` on each, for `seconds`, reporting
/// throughput and latency once every connection is done. A connection that
/// drops (the proxy or parent closed it, or something went wrong) is simply
/// reopened: what is measured is the proxy's throughput, not this tool's
/// tolerance for a single dropped socket.
async fn bench(mut args: impl Iterator<Item = String>) -> ExitCode {
    let (Some(proxy_addr), Some(origin_authority), Some(connections), Some(seconds)) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        eprintln!(
            "usage: gatir-loadgen bench <proxy-host:port> <origin-host:port> <connections> <seconds>"
        );
        return ExitCode::from(2);
    };
    let Ok(connections) = connections.parse::<usize>() else {
        eprintln!("connections must be a number: {connections}");
        return ExitCode::from(2);
    };
    let Ok(seconds) = seconds.parse::<u64>() else {
        eprintln!("seconds must be a number: {seconds}");
        return ExitCode::from(2);
    };
    let Ok(uri) = format!("http://{origin_authority}/").parse::<Uri>() else {
        eprintln!("not a valid host:port: {origin_authority}");
        return ExitCode::from(2);
    };

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let total = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let latencies: Arc<Mutex<Vec<u128>>> = Arc::new(Mutex::new(Vec::new()));

    let mut workers = Vec::with_capacity(connections);
    for _ in 0..connections {
        let proxy_addr = proxy_addr.clone();
        let uri = uri.clone();
        let host_header = origin_authority.clone();
        let total = total.clone();
        let errors = errors.clone();
        let latencies = latencies.clone();

        workers.push(tokio::spawn(async move {
            let mut local_latencies = Vec::new();

            'reconnect: while Instant::now() < deadline {
                let Ok(stream) = TcpStream::connect(&proxy_addr).await else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let Ok((mut sender, connection)) = http1::Builder::new()
                    .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
                    .await
                else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                tokio::spawn(async move {
                    if let Err(err) = connection.await {
                        eprintln!("connection ended: {err}");
                    }
                });

                while Instant::now() < deadline {
                    let mut request = Request::new(Empty::<Bytes>::new());
                    *request.method_mut() = Method::GET;
                    *request.uri_mut() = uri.clone();
                    request.headers_mut().insert(
                        HOST,
                        host_header
                            .parse()
                            .expect("a host:port is a valid Host value"),
                    );

                    let start = Instant::now();
                    let Ok(response) = sender.send_request(request).await else {
                        errors.fetch_add(1, Ordering::Relaxed);
                        continue 'reconnect;
                    };
                    let ok = response.status().is_success();
                    let Ok(collected) = response.into_body().collect().await else {
                        errors.fetch_add(1, Ordering::Relaxed);
                        continue 'reconnect;
                    };
                    let _ = collected.to_bytes();
                    if ok {
                        total.fetch_add(1, Ordering::Relaxed);
                        local_latencies.push(start.elapsed().as_micros());
                    } else {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            latencies.lock().await.extend(local_latencies);
        }));
    }
    for worker in workers {
        let _ = worker.await;
    }

    let mut all = latencies.lock().await.clone();
    all.sort_unstable();
    let count = total.load(Ordering::Relaxed);
    let percentile = |p: f64| -> u128 {
        if all.is_empty() {
            return 0;
        }
        all[((all.len() as f64 - 1.0) * p).round() as usize]
    };
    println!(
        "connections={connections} requests={count} errors={} seconds={seconds} rps={:.1}",
        errors.load(Ordering::Relaxed),
        count as f64 / seconds as f64
    );
    println!(
        "latency_us: p50={} p90={} p95={} p99={} max={}",
        percentile(0.50),
        percentile(0.90),
        percentile(0.95),
        percentile(0.99),
        all.last().copied().unwrap_or(0)
    );
    ExitCode::SUCCESS
}
