//! `gatir pac export` and `gatir pac test`, run as a person runs them.

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

const OVERRIDES: &str = "[[pac.overrides]]\n\
hosts = [\"ghcr.io\", \"githubusercontent.com\"]\n\
proxy = \"PROXY a.example.com:80; PROXY b.example.com:80\"\n";

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

/// A folder with the script of the company and a configuration that has
/// overrides of it.
fn workdir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("original.pac"), ORIGINAL).unwrap();
    configure(
        dir.path(),
        &format!("[pac]\nfile = \"original.pac\"\n{OVERRIDES}"),
    );
    dir
}

fn configure(dir: &Path, toml: &str) {
    fs::write(dir.join("gatir.toml"), toml).unwrap();
}

fn export(dir: &Path, output: &str) -> Command {
    let mut command = gatir(dir);
    command.args(["pac", "export", "--output", output]);
    command
}

#[test]
fn a_file_name_alone_goes_to_the_pac_folder_and_the_original_is_kept() {
    let dir = workdir();
    export(dir.path(), "local.pac").assert().success().stdout(
        predicate::str::contains(
            "override:    ghcr.io, githubusercontent.com -> PROXY a.example.com:80; PROXY b.example.com:80",
        )
        .and(predicate::str::contains(
            "checked:     ghcr.io -> PROXY a.example.com:80",
        ))
        .and(predicate::str::contains("local.pac")),
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
fn without_an_output_the_script_goes_to_the_standard_output_and_nothing_else() {
    let dir = workdir();
    let assert = gatir(dir.path())
        .args(["pac", "export"])
        .assert()
        .success()
        .stderr("");
    let out = assert.get_output().stdout.clone();
    assert!(out.starts_with(ORIGINAL.as_bytes()));
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("\"githubusercontent.com\""), "{text}");
    assert!(text.ends_with("// ===== end of gatir: local routes =====\n"));
    assert!(!dir.path().join("pac").exists());
}

#[test]
fn several_overrides_are_all_in_the_script() {
    let dir = workdir();
    configure(
        dir.path(),
        &format!(
            "[pac]\nfile = \"original.pac\"\n{OVERRIDES}\
             [[pac.overrides]]\nhosts = [\"*.crates.io\"]\nproxy = \"DIRECT\"\n"
        ),
    );
    export(dir.path(), "local.pac").assert().success().stdout(
        predicate::str::contains("-> PROXY a.example.com:80; PROXY b.example.com:80")
            .and(predicate::str::contains("*.crates.io -> DIRECT")),
    );
    let made = fs::read_to_string(dir.path().join("pac").join("local.pac")).unwrap();
    assert!(made.contains("\"*.crates.io\""), "{made}");
    assert_eq!(made.matches("// ===== gatir: local routes").count(), 1);
}

#[test]
fn a_path_is_taken_as_written() {
    let dir = workdir();
    let elsewhere = tempfile::tempdir().unwrap();
    let absolute = elsewhere.path().join("deep").join("abs.pac");

    export(dir.path(), absolute.to_str().unwrap())
        .assert()
        .success();
    assert!(absolute.is_file());

    // `./name` is the current folder, not the pac folder.
    export(dir.path(), "./here.pac").assert().success();
    assert!(dir.path().join("here.pac").is_file());
    assert!(!dir.path().join("pac").exists());
}

#[test]
fn the_default_folder_is_in_the_users_configuration_folder() {
    let dir = workdir();
    let home = tempfile::tempdir().unwrap();
    let folder = home.path().join("gatir");
    fs::create_dir_all(&folder).unwrap();
    fs::write(
        folder.join("gatir.toml"),
        format!(
            "[pac]\nfile = {:?}\n{OVERRIDES}",
            dir.path().join("original.pac").display().to_string()
        ),
    )
    .unwrap();
    Command::cargo_bin("gatir")
        .unwrap()
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("NO_COLOR")
        .current_dir(dir.path())
        .args(["pac", "export", "--output", "x.pac"])
        .assert()
        .success();
    assert!(folder.join("pac").join("x.pac").is_file());
}

#[test]
fn an_existing_file_is_not_replaced_without_force() {
    let dir = workdir();
    export(dir.path(), "local.pac").assert().success();
    let path = dir.path().join("pac").join("local.pac");
    fs::write(&path, "kept\n").unwrap();

    export(dir.path(), "local.pac").assert().failure().stderr(
        predicate::str::contains("exists already").and(predicate::str::contains("--force")),
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "kept\n");

    export(dir.path(), "local.pac")
        .arg("--force")
        .assert()
        .success()
        .stdout(predicate::str::contains("kept as"));
    assert_eq!(
        fs::read_to_string(dir.path().join("pac").join("local.pac.prev")).unwrap(),
        "kept\n"
    );
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("gatir: local routes")
    );
}

#[test]
fn what_cannot_be_made_creates_nothing() {
    let dir = workdir();
    for (what, toml) in [
        (
            "bad host",
            "[pac]\nfile = \"original.pac\"\n[[pac.overrides]]\nhosts = [\"http://nope\"]\n\
             proxy = \"DIRECT\"\n",
        ),
        (
            "bad proxy",
            "[pac]\nfile = \"original.pac\"\n[[pac.overrides]]\nhosts = [\"a.com\"]\n\
             proxy = \"FTP z\"\n",
        ),
        (
            "missing source",
            "[pac]\nfile = \"nowhere.pac\"\n[[pac.overrides]]\nhosts = [\"a.com\"]\n\
             proxy = \"DIRECT\"\n",
        ),
        (
            "not a script",
            "[pac]\nfile = \"text.pac\"\n[[pac.overrides]]\nhosts = [\"a.com\"]\n\
             proxy = \"DIRECT\"\n",
        ),
        ("no script at all", "parents = [\"p.example.com:80\"]\n"),
    ] {
        fs::write(dir.path().join("text.pac"), "just words\n").unwrap();
        configure(dir.path(), toml);
        export(dir.path(), "x.pac").assert().failure();
        assert!(!dir.path().join("pac").exists(), "{what}");
    }
}

#[test]
fn an_override_that_another_hides_is_named() {
    let dir = workdir();
    configure(
        dir.path(),
        "[pac]\nfile = \"original.pac\"\n\
         [[pac.overrides]]\nhosts = [\"*.example.com\"]\nproxy = \"DIRECT\"\n\
         [[pac.overrides]]\nhosts = [\"one.example.com\"]\nproxy = \"PROXY a.example.com:80\"\n",
    );
    export(dir.path(), "x.pac")
        .assert()
        .failure()
        .stderr(predicate::str::contains("one.example.com"));
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
    configure(
        dir.path(),
        &format!("[pac]\nurl = {address:?}\n{OVERRIDES}"),
    );
    export(dir.path(), "fetched.pac")
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
fn test_shows_what_the_overrides_change() {
    let dir = workdir();

    let assert = gatir(dir.path())
        .args(["pac", "test"])
        .args([
            "ghcr.io",
            "https://pkg.githubusercontent.com/x",
            "http://app.internal.example.com/",
        ])
        .assert()
        .success();
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    // The hosts of the overrides differ; the others do not.
    let block = |url: &str| -> String {
        let start = text.find(url).unwrap_or_else(|| panic!("{url} in {text}"));
        text[start..].lines().take(3).collect::<Vec<_>>().join("\n")
    };
    let ghcr = block("https://ghcr.io/");
    assert!(ghcr.contains("(differs)"), "{ghcr}");
    assert!(
        ghcr.contains("original") && ghcr.contains("PROXY zscaler.example.com:9000"),
        "{ghcr}"
    );
    assert!(
        ghcr.contains("with overrides")
            && ghcr.contains("PROXY a.example.com:80; PROXY b.example.com:80"),
        "{ghcr}"
    );
    assert!(block("https://pkg.githubusercontent.com/x").contains("(differs)"));
    let internal = block("http://app.internal.example.com/");
    assert!(!internal.contains("(differs)"), "{internal}");
    assert!(internal.contains("DIRECT"), "{internal}");
}

#[test]
fn test_compares_scripts_that_are_named_as_they_are() {
    let dir = workdir();
    export(dir.path(), "local.pac").assert().success();

    // --script is the file as it is, without the overrides of the configuration:
    // here the exported file already has them.
    gatir(dir.path())
        .args([
            "pac",
            "test",
            "--script",
            "./original.pac",
            "--script",
            "local.pac",
        ])
        .arg("ghcr.io")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("(differs)")
                .and(predicate::str::contains(
                    "original.pac  PROXY zscaler.example.com:9000",
                ))
                .and(predicate::str::contains(
                    "local.pac     PROXY a.example.com:80",
                )),
        );
}

#[test]
fn test_without_overrides_shows_one_answer() {
    let dir = workdir();
    configure(dir.path(), "[pac]\nfile = \"original.pac\"\n");

    gatir(dir.path())
        .args(["pac", "test", "ghcr.io"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "https://ghcr.io/  ->  PROXY zscaler.example.com:9000",
        ));

    // No script anywhere: it says so.
    configure(dir.path(), "parents = [\"p.example.com:80\"]\n");
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
async fn an_exported_script_is_what_the_proxy_runs() {
    // End to end: the file made by the command, used as the script of a proxy
    // that has no overrides of its own, sends the requests where the
    // overrides say.
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
    configure(
        dir.path(),
        &format!(
            "[pac]\nfile = \"original.pac\"\n[[pac.overrides]]\n\
             hosts = [\"special.example.com\"]\nproxy = \"PROXY {}\"\n",
            local.addr()
        ),
    );
    let dir_path = dir.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        export(&dir_path, "copy.pac").assert().success();
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
            predicate::str::contains("original.pac")
                .and(predicate::str::contains("pac folder"))
                .and(predicate::str::contains("write ./NAME")),
        );
}
