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

#[test]
fn hash_prints_the_nt_hash_line_for_the_configuration() {
    // The NT hash of "Password" is a published MS-NLMP test vector.
    gatir()
        .args(["hash", "--stdin"])
        .write_stdin("Password\n")
        .assert()
        .success()
        .stdout("nt_hash = \"a4f49c406510bdcab6824ee7c30fd852\"\n")
        .stderr(predicate::str::contains("[credentials]"));
}

#[test]
fn hash_ignores_the_line_ending_of_the_input() {
    for input in ["Password\n", "Password\r\n", "Password"] {
        gatir()
            .args(["hash", "--stdin"])
            .write_stdin(input)
            .assert()
            .success()
            .stdout(predicate::str::contains("a4f49c406510bdcab6824ee7c30fd852"));
    }
}

#[test]
fn hash_uses_utf16_for_non_ascii_passwords() {
    // Cross-checked against an independent MD4 implementation.
    gatir()
        .args(["hash", "--stdin"])
        .write_stdin("p\u{e4}ssw\u{f6}rd\n")
        .assert()
        .success()
        .stdout("nt_hash = \"0553152250ac01adb4213cb9938663e4\"\n");
}

#[test]
fn hash_rejects_an_empty_password() {
    gatir()
        .args(["hash", "--stdin"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty"));
}

#[test]
fn hash_never_echoes_the_password() {
    gatir()
        .args(["hash", "--stdin"])
        .write_stdin("my-very-secret-password\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("my-very-secret-password").not())
        .stderr(predicate::str::contains("my-very-secret-password").not());
}

#[test]
fn the_hash_line_is_accepted_by_the_configuration() {
    let output = gatir()
        .args(["hash", "--stdin"])
        .write_stdin("Password\n")
        .output()
        .unwrap();
    let hash_line = String::from_utf8(output.stdout).unwrap();

    let file = config_file(&format!(
        "[credentials]\nusername = \"alice\"\ndomain = \"EXAMPLE\"\n{hash_line}"
    ));
    gatir()
        .args(["config", "check", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("secret: nt_hash (hidden)"));
}

#[test]
fn config_check_lists_the_tunnels_of_the_file_and_the_command_line() {
    let file =
        config_file("[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"file.example.com:22\"\n");
    gatir()
        .args(["config", "check", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "127.0.0.1:2222 -> file.example.com:22",
        ));

    // -L takes the place of the ones in the file.
    gatir()
        .args([
            "config",
            "check",
            "-L",
            "3333:cli.example.com:5432",
            "-L",
            "[::1]:4444:[2001:db8::1]:22",
        ])
        .args(["--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("127.0.0.1:3333 -> cli.example.com:5432")
                .and(predicate::str::contains("[::1]:4444 -> [2001:db8::1]:22"))
                .and(predicate::str::contains("file.example.com").not()),
        );
}

#[test]
fn a_tunnel_that_is_not_one_is_refused_with_the_reason() {
    gatir()
        .args(["config", "check", "-L", "2222:git"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "expected [BIND:]PORT:HOST:HOSTPORT",
        ));
}

#[test]
fn config_check_reports_the_socks5_server_without_its_password() {
    let file = config_file(
        "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = \"hush-socks-pw\"\n",
    );
    gatir()
        .args(["config", "check", "--log-level", "trace", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("127.0.0.1:1080")
                .and(predicate::str::contains("user name \"bob\""))
                .and(predicate::str::contains("hush-socks-pw").not()),
        )
        .stderr(predicate::str::contains("hush-socks-pw").not());

    // --socks5 takes the place of the addresses.
    gatir()
        .args(["config", "check", "--socks5", "127.0.0.1:2080", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("127.0.0.1:2080")
                .and(predicate::str::contains("127.0.0.1:1080").not()),
        );
}
