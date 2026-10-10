//! `gatir pac generate` and `gatir pac test`, run as a person runs them.

mod common;

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use common::*;
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};
use predicates::prelude::*;
use tempfile::TempDir;

const ORIGINAL: &str = "// the company's script\n\
function FindProxyForURL(url, host) {\n\
\tif (dnsDomainIs(host, \".internal.example.com\")) return \"DIRECT\";\n\
\treturn \"PROXY zscaler.example.com:9000\";\n\
}\n";

/// A gatir that finds nothing of the machine it runs on: its configuration
/// folder is `dir`, so the `pac` folder is `dir/pac`.
fn gatir(dir: &Path) -> Command {
    let mut command = Command::cargo_bin("gatir").unwrap();
    command
        .env("HOME", "/nonexistent/gatir-test-home")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("NO_COLOR")
        .current_dir(dir)
        .arg("--config")
        .arg(dir.join("gatir.toml"));
    command
}

fn workdir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("original.pac"), ORIGINAL).unwrap();
    dir
}

fn generate(dir: &Path, output: &str) -> Command {
    let mut command = gatir(dir);
    command
        .args(["pac", "generate", "--from", "./original.pac"])
        .args(["--host", "ghcr.io", "--host", "githubusercontent.com"])
        .args(["--proxy", "PROXY a.example.com:80; PROXY b.example.com:80"])
        .args(["--output", output]);
    command
}

#[test]
fn a_file_name_alone_goes_to_the_pac_folder_and_the_original_is_kept() {
    let dir = workdir();
    generate(dir.path(), "local.pac").assert().success().stdout(
        predicate::str::contains("ghcr.io, githubusercontent.com -> PROXY a.example.com:80")
            .and(
                predicate::str::contains("file = 'pac/local.pac'")
                    .or(predicate::str::contains("local.pac'")),
            )
            .and(predicate::str::contains(
                "checked:     ghcr.io -> PROXY a.example.com:80",
            )),
    );

    let made = fs::read(dir.path().join("pac").join("local.pac")).unwrap();
    assert!(made.starts_with(ORIGINAL.as_bytes()));
    assert!(
        String::from_utf8(made)
            .unwrap()
            .contains("gatir: local routes")
    );
    // Nothing else was left in the folder.
    let names: Vec<_> = fs::read_dir(dir.path().join("pac"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["local.pac"]);
}

#[test]
fn a_path_is_taken_as_written() {
    let dir = workdir();
    let elsewhere = tempfile::tempdir().unwrap();
    let absolute = elsewhere.path().join("deep").join("abs.pac");

    generate(dir.path(), absolute.to_str().unwrap())
        .assert()
        .success();
    assert!(absolute.is_file());

    // `./name` is the current folder, not the pac folder.
    generate(dir.path(), "./here.pac").assert().success();
    assert!(dir.path().join("here.pac").is_file());
    assert!(!dir.path().join("pac").exists());
}

#[test]
fn the_default_folder_is_in_the_users_configuration_folder() {
    let dir = workdir();
    let home = tempfile::tempdir().unwrap();
    Command::cargo_bin("gatir")
        .unwrap()
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("NO_COLOR")
        .current_dir(dir.path())
        .args(["pac", "generate", "--from", "./original.pac"])
        .args([
            "--host", "ghcr.io", "--proxy", "DIRECT", "--output", "x.pac",
        ])
        .assert()
        .success();
    assert!(
        home.path()
            .join("gatir")
            .join("pac")
            .join("x.pac")
            .is_file()
    );
}

#[test]
fn an_existing_file_is_not_replaced_without_force() {
    let dir = workdir();
    generate(dir.path(), "local.pac").assert().success();
    let path = dir.path().join("pac").join("local.pac");
    // The person adds a host by hand.
    let edited = fs::read_to_string(&path)
        .unwrap()
        .replace("\"ghcr.io\"", "\"ghcr.io\",\n\t\t\t\t\"static.crates.io\"");
    fs::write(&path, &edited).unwrap();

    generate(dir.path(), "local.pac").assert().failure().stderr(
        predicate::str::contains("exists already").and(predicate::str::contains("--force")),
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), edited);

    generate(dir.path(), "local.pac")
        .arg("--force")
        .assert()
        .success()
        .stdout(predicate::str::contains("kept as"));
    assert_eq!(
        fs::read_to_string(dir.path().join("pac").join("local.pac.prev")).unwrap(),
        edited
    );
    assert!(
        !fs::read_to_string(&path)
            .unwrap()
            .contains("static.crates.io")
    );
}

#[test]
fn what_cannot_be_made_creates_nothing() {
    let dir = workdir();
    for (what, mut command) in [
        ("bad host", {
            let mut c = generate(dir.path(), "x.pac");
            c.args(["--host", "http://nope"]);
            c
        }),
        ("bad proxy", {
            let mut c = gatir(dir.path());
            c.args([
                "pac",
                "generate",
                "--from",
                "./original.pac",
                "--host",
                "a.com",
            ])
            .args(["--proxy", "FTP z", "--output", "x.pac"]);
            c
        }),
        ("missing source", {
            let mut c = gatir(dir.path());
            c.args([
                "pac",
                "generate",
                "--from",
                "./nowhere.pac",
                "--host",
                "a.com",
            ])
            .args(["--proxy", "DIRECT", "--output", "x.pac"]);
            c
        }),
        ("not a script", {
            fs::write(dir.path().join("text.pac"), "just words\n").unwrap();
            let mut c = gatir(dir.path());
            c.args(["pac", "generate", "--from", "./text.pac", "--host", "a.com"])
                .args(["--proxy", "DIRECT", "--output", "x.pac"]);
            c
        }),
    ] {
        command.assert().failure();
        assert!(!dir.path().join("pac").exists(), "{what}");
    }
}

#[test]
fn a_script_can_be_fetched_from_an_address() {
    // The runtime of the test is busy serving: the command runs on another thread.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let origin = runtime.block_on(MockOrigin::start(|_| Reply::ok(ORIGINAL)));
    let dir = workdir();

    let address = format!("http://{}/proxy.pac?token=secret", origin.authority());
    gatir(dir.path())
        .args(["pac", "generate", "--from", &address])
        .args([
            "--host",
            "ghcr.io",
            "--proxy",
            "DIRECT",
            "--output",
            "fetched.pac",
        ])
        .assert()
        .success()
        // The query may hold a token: it is not printed, nor written down.
        .stdout(predicate::str::contains("secret").not());
    let made = fs::read_to_string(dir.path().join("pac").join("fetched.pac")).unwrap();
    assert!(made.starts_with(ORIGINAL));
    assert!(!made.contains("secret"));
    assert!(made.contains(&format!("from http://{}/proxy.pac.", origin.authority())));
}

#[test]
fn test_shows_what_a_copy_changes() {
    let dir = workdir();
    generate(dir.path(), "local.pac").assert().success();

    let assert = gatir(dir.path())
        .args([
            "pac",
            "test",
            "--script",
            "./original.pac",
            "--script",
            "local.pac",
        ])
        .args([
            "ghcr.io",
            "https://pkg.githubusercontent.com/x",
            "http://app.internal.example.com/",
        ])
        .assert()
        .success();
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    // The hosts of the rule differ; the others do not.
    let block = |url: &str| -> String {
        let start = text.find(url).unwrap_or_else(|| panic!("{url} in {text}"));
        text[start..].lines().take(3).collect::<Vec<_>>().join("\n")
    };
    let ghcr = block("https://ghcr.io/");
    assert!(ghcr.contains("(differs)"), "{ghcr}");
    assert!(
        ghcr.contains("original.pac") && ghcr.contains("PROXY zscaler.example.com:9000"),
        "{ghcr}"
    );
    assert!(
        ghcr.contains("local.pac")
            && ghcr.contains("PROXY a.example.com:80; PROXY b.example.com:80"),
        "{ghcr}"
    );
    assert!(block("https://pkg.githubusercontent.com/x").contains("(differs)"));
    let internal = block("http://app.internal.example.com/");
    assert!(!internal.contains("(differs)"), "{internal}");
    assert!(internal.contains("DIRECT"), "{internal}");
}

#[test]
fn test_without_a_script_asks_the_one_of_the_configuration() {
    let dir = workdir();
    generate(dir.path(), "local.pac").assert().success();
    fs::write(
        dir.path().join("gatir.toml"),
        "[pac]\nfile = \"pac/local.pac\"\n",
    )
    .unwrap();

    gatir(dir.path())
        .args(["pac", "test", "ghcr.io"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "https://ghcr.io/  ->  PROXY a.example.com:80",
        ));

    // No script anywhere: it says so.
    fs::write(
        dir.path().join("gatir.toml"),
        "parents = [\"p.example.com:80\"]\n",
    )
    .unwrap();
    gatir(dir.path())
        .args(["pac", "test", "ghcr.io"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no PAC script"));
}

#[test]
fn test_fails_when_a_script_cannot_be_used() {
    let dir = workdir();
    gatir(dir.path())
        .args([
            "pac",
            "test",
            "--script",
            "./original.pac",
            "--script",
            "./missing.pac",
            "ghcr.io",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("PROXY zscaler.example.com:9000"))
        .stdout(predicate::str::contains("error: cannot read"));
}

#[tokio::test]
async fn a_generated_script_is_what_the_proxy_runs() {
    // End to end: the copy made by the command is the script of a proxy, and
    // the requests go where it says.
    let (company, local) = (
        MockOrigin::start(|_| Reply::ok("company")).await,
        MockOrigin::start(|_| Reply::ok("local")).await,
    );
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("original.pac"),
        format!(
            "function FindProxyForURL(url, host) {{ return \"PROXY {}\"; }}\n",
            company.addr()
        ),
    )
    .unwrap();
    let dir_path = dir.path().to_path_buf();
    let proxy_list = format!("PROXY {}", local.addr());
    tokio::task::spawn_blocking(move || {
        gatir(&dir_path)
            .args(["pac", "generate", "--from", "./original.pac"])
            .args(["--host", "special.example.com", "--proxy", &proxy_list])
            .args(["--output", "copy.pac"])
            .assert()
            .success();
    })
    .await
    .unwrap();

    let table = format!(
        "[pac]\nfile = {:?}\n",
        dir.path()
            .join("pac")
            .join("copy.pac")
            .display()
            .to_string()
    );
    let proxy = start_proxy(&table).await;
    let body = |authority: &'static str| {
        let addr = proxy.addr;
        async move {
            let mut client = RawClient::connect(addr).await.unwrap();
            client.send(get(authority, "/", "")).await.unwrap();
            client.read_response(false).await.unwrap().body_text()
        }
    };
    assert_eq!(body("special.example.com").await, "local");
    assert_eq!(body("www.special.example.com").await, "local");
    assert_eq!(body("other.example.com").await, "company");
}

#[test]
fn a_file_name_alone_that_is_not_in_the_pac_folder_says_where_it_looked() {
    let dir = workdir();
    // original.pac is in the current folder, not in the pac folder.
    gatir(dir.path())
        .args(["pac", "test", "--script", "original.pac", "ghcr.io"])
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("pac/original.pac")
                .and(predicate::str::contains("write ./NAME")),
        );
}
