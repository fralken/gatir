//! A running gatir reads its configuration again when it gets SIGHUP. The
//! process here is the real binary, and the signal is a real one.

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::get;
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};

/// gatir running as a process, with what it logs collected.
struct Running {
    child: Child,
    log: Arc<Mutex<String>>,
}

impl Running {
    fn start(config: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gatir"))
            .args(["run", "--log-level", "info", "--config"])
            .arg(config)
            .env("HOME", "/nonexistent/gatir-test-home")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("RUST_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start gatir");
        let log = Arc::new(Mutex::new(String::new()));
        let stderr = child.stderr.take().unwrap();
        let collected = log.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut log = collected.lock().unwrap();
                log.push_str(&line);
                log.push('\n');
            }
        });
        Self { child, log }
    }

    fn hang_up(&self) {
        let status = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .expect("send SIGHUP");
        assert!(status.success());
    }

    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// Waits until what gatir logged satisfies `wanted`.
    async fn logged(&self, what: &str, wanted: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !wanted(&self.log()) {
            assert!(
                Instant::now() < deadline,
                "gatir never logged {what}: {}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn named(name: &'static str) -> MockOrigin {
    MockOrigin::start(move |_| Reply::ok(name)).await
}

async fn free_port() -> u16 {
    tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn answer(proxy: SocketAddr) -> String {
    let mut client = RawClient::connect(proxy).await.unwrap();
    client.send(get("site.test", "/", "")).await.unwrap();
    client.read_response(false).await.unwrap().body_text()
}

/// Waits until the proxy answers with `expected`.
async fn answers(proxy: SocketAddr, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(Ok(text)) =
            tokio::time::timeout(Duration::from_secs(2), tokio::spawn(answer(proxy))).await
            && text == expected
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the proxy never answered {expected:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn sighup_makes_gatir_read_its_configuration_again() {
    let (a, b) = (named("A").await, named("B").await);
    let port = free_port().await;
    let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gatir.toml");
    let write = |parent: &str, listen: SocketAddr| {
        std::fs::write(
            &file,
            format!("listen = [\"{listen}\"]\nparents = [\"{parent}\"]\n"),
        )
        .unwrap();
    };

    write(&a.authority(), proxy);
    let mut gatir = Running::start(&file);
    answers(proxy, "A").await;

    // A new parent.
    write(&b.authority(), proxy);
    gatir.hang_up();
    answers(proxy, "B").await;
    gatir
        .logged("that it reloaded", |log| {
            log.contains("configuration reloaded")
        })
        .await;
    assert!(gatir.alive());

    // A file that is wrong changes nothing, and gatir says why.
    std::fs::write(&file, "parents = [\"no-port\"]\n").unwrap();
    gatir.hang_up();
    gatir
        .logged("the refusal", |log| {
            log.contains("keeping the settings in use")
        })
        .await;
    assert_eq!(answer(proxy).await, "B");
    assert!(gatir.alive());

    // A setting that only a new start applies is said to need one.
    write(
        &a.authority(),
        format!("127.0.0.1:{}", free_port().await).parse().unwrap(),
    );
    gatir.hang_up();
    gatir
        .logged("the restart notice", |log| {
            log.contains("take effect only when gatir is started again")
        })
        .await;
    // The rest of that file did apply, and the address is the one it had.
    answers(proxy, "A").await;

    // And it goes on working after all of that.
    write(&b.authority(), proxy);
    gatir.hang_up();
    answers(proxy, "B").await;
    assert!(gatir.alive());
}
