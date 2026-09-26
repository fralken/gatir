//! A script that cannot be interrupted from inside: a long loop in a built-in
//! function. Its worker is given up on and replaced.
//!
//! This has its own test binary because the stuck threads keep running until
//! the process ends, and should not slow down other tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use gatir::pac::{Pac, PacEnv, PacError, PacLimits, ProxyAddr, Route, SystemResolver};

fn env() -> PacEnv {
    PacEnv::system(Arc::new(SystemResolver::new(
        Duration::from_secs(2),
        Duration::from_secs(60),
    )))
}

#[tokio::test]
async fn a_worker_stuck_in_a_built_in_is_given_up_on_and_replaced() {
    let pac = Pac::load(
        r#"function FindProxyForURL(url, host) {
               if (host === "stuck") { return new Array(4294967295).join("x"); }
               return "PROXY ok:1";
           }"#,
        PacLimits {
            time: Duration::from_millis(200),
            grace: Duration::from_millis(200),
            workers: 1,
            ..PacLimits::default()
        },
        env(),
    )
    .unwrap();
    let ok = [Route::Proxy(ProxyAddr {
        host: "ok".to_owned(),
        port: 1,
    })];

    for round in 1..=2 {
        let started = Instant::now();
        let error = pac.find("http://stuck/", "stuck").await.unwrap_err();
        assert!(
            matches!(error, PacError::Timeout(_)),
            "round {round}: {error}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "round {round}: {:?}",
            started.elapsed()
        );

        // The single worker is stuck, but a fresh one answers.
        assert_eq!(
            pac.find("http://x/", "fine").await.unwrap(),
            ok,
            "round {round}"
        );
    }
}

#[tokio::test]
async fn the_system_resolver_works_inside_the_script() {
    let pac = Pac::load(
        r#"function FindProxyForURL(url, host) {
               var ip = dnsResolve("localhost");
               return ip && isInNet(ip, "127.0.0.0", "255.0.0.0") && isResolvable("localhost")
                   ? "PROXY loopback:1" : "DIRECT";
           }"#,
        PacLimits::default(),
        env(),
    )
    .unwrap();
    let routes = pac.find("http://x/", "x").await.unwrap();
    assert_eq!(
        routes,
        [Route::Proxy(ProxyAddr {
            host: "loopback".to_owned(),
            port: 1
        })]
    );
}
