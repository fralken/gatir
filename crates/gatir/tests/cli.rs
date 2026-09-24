use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

fn gatir() -> Command {
    Command::cargo_bin("gatir").unwrap()
}

fn config_file(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

const VALID: &str = r#"
    listen = ["127.0.0.1:3128"]
    parents = ["proxy.example.com:8080"]

    [credentials]
    username = "alice"
    domain = "EXAMPLE"
    password = "hunter2-secret"
"#;

#[test]
fn prints_the_version() {
    gatir()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn without_arguments_it_shows_help_and_fails() {
    gatir()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn help_lists_the_options() {
    gatir()
        .args(["config", "check", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--config")
                .and(predicate::str::contains("--parent"))
                .and(predicate::str::contains("--password-prompt"))
                .and(predicate::str::contains("--password ").not()),
        );
}

#[test]
fn config_check_accepts_a_valid_file_without_printing_secrets() {
    let file = config_file(VALID);
    gatir()
        .args(["config", "check", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("configuration OK")
                .and(predicate::str::contains("proxy.example.com:8080"))
                .and(predicate::str::contains("alice@EXAMPLE"))
                .and(predicate::str::contains("hunter2-secret").not()),
        )
        .stderr(predicate::str::contains("hunter2-secret").not());
}

#[test]
fn debug_logging_never_prints_secrets() {
    let file = config_file(VALID);
    gatir()
        .args(["config", "check", "--log-level", "trace", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2-secret").not())
        .stderr(
            predicate::str::contains("configuration loaded")
                .and(predicate::str::contains("hunter2-secret").not()),
        );
}

#[test]
fn config_check_reports_invalid_files() {
    let file =
        config_file("[credentials]\nusername = \"alice\"\npassword = \"topsecret\" garbage\n");
    gatir()
        .args(["config", "check", "--config"])
        .arg(file.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("invalid config at")
                .and(predicate::str::contains("topsecret").not()),
        );
}

#[test]
fn config_check_reports_a_missing_file() {
    gatir()
        .args(["config", "check", "--config", "/nonexistent/gatir.toml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read config file"));
}

#[test]
fn command_line_options_override_the_file() {
    let file = config_file(VALID);
    gatir()
        .args([
            "config",
            "check",
            "--parent",
            "other.example.com:3128",
            "--config",
        ])
        .arg(file.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("other.example.com:3128")
                .and(predicate::str::contains("proxy.example.com").not()),
        );
}

#[test]
fn config_check_summarizes_access_rules_and_no_proxy() {
    let file = config_file(
        r#"
        no_proxy = ["localhost", "*.corp.example.com"]

        [access]
        default = "deny"
        rules = [{ allow = "127.0.0.1" }, { allow = "10.0.0.0/8" }]
        "#,
    );
    gatir()
        .args(["config", "check", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains(
                "default deny; first match wins: allow 127.0.0.1/32, allow 10.0.0.0/8",
            )
            .and(predicate::str::contains("localhost, *.corp.example.com")),
        );
}

#[test]
fn config_check_rejects_a_host_name_in_an_access_rule() {
    let file = config_file("[access]\nrules = [{ allow = \"example.com\" }]\n");
    gatir()
        .args(["config", "check", "--config"])
        .arg(file.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("host names are not supported"));
}

#[test]
fn config_check_works_without_a_file() {
    gatir().args(["config", "check"]).assert().success().stdout(
        predicate::str::contains("127.0.0.1:3128")
            .and(predicate::str::contains("direct connections")),
    );
}

#[test]
fn header_values_are_never_printed() {
    let file = config_file("[headers]\nX-Api-Key = \"super-secret-key\"\n");
    gatir()
        .args(["config", "check", "--log-level", "trace", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("x-api-key")
                .and(predicate::str::contains("super-secret-key").not()),
        )
        .stderr(predicate::str::contains("super-secret-key").not());
}
