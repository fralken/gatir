//! A PAC script with a local rule added to it: some hosts go to the proxies
//! named, and everything else is left to the script as it was.
//!
//! The script is kept byte for byte. The rule is a block appended after it,
//! which wraps `FindProxyForURL` (and `FindProxyForURLEx`, if there is one) and
//! answers first. Nothing depends on how the script writes its function, and
//! the block is plain JavaScript that a person can read and edit: the hosts are
//! a list of strings, and another rule is another entry of `routes`.

use std::fmt::Write as _;
use std::sync::Arc;

use super::{Pac, PacEnv, PacError, PacLimits, Resolver, Route, parse};

/// The longest host name accepted.
const MAX_NAME: usize = 253;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenerateError {
    #[error("no host was given: name at least one with --host")]
    NoHosts,
    #[error(
        "{0:?} is not a host name: give a name such as example.com, with no scheme, port or \
         path (* and ? stand for any text)"
    )]
    BadHost(String),
    #[error("the proxy list is empty: give one such as \"PROXY proxy.example.com:8080\"")]
    NoProxy,
    #[error(
        "{0:?} is not a proxy: a list is made of DIRECT and PROXY host:port entries, \
         separated by semicolons"
    )]
    BadProxy(String),
    #[error("the result is not a usable PAC script: {0}")]
    Script(String),
}

/// Which hosts are sent to which proxies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    hosts: Vec<String>,
    /// The list as it is written in the script, in its canonical form.
    proxy: String,
    routes: Vec<Route>,
}

impl Rule {
    /// `hosts` are names, which cover the domain and its sub-domains, or
    /// patterns with `*` and `?`. `proxy` is a PAC result: `PROXY a:80; PROXY
    /// b:80`, or `DIRECT`.
    pub fn new(hosts: &[String], proxy: &str) -> Result<Self, GenerateError> {
        let mut names: Vec<String> = Vec::new();
        for host in hosts {
            let name = host_name(host)?;
            if !names.contains(&name) {
                names.push(name);
            }
        }
        if names.is_empty() {
            return Err(GenerateError::NoHosts);
        }

        let parsed = parse(proxy);
        if let Some(entry) = parsed.ignored.first() {
            return Err(GenerateError::BadProxy(entry.clone()));
        }
        if parsed.routes.is_empty() {
            return Err(GenerateError::NoProxy);
        }
        let proxy = parsed
            .routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        Ok(Self {
            hosts: names,
            proxy,
            routes: parsed.routes,
        })
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The proxy list as it is written in the script.
    pub fn proxy(&self) -> &str {
        &self.proxy
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// The entries that gatir does not use (HTTPS and SOCKS proxies). A browser
    /// may, so they are allowed.
    pub fn unused(&self) -> Vec<String> {
        self.routes
            .iter()
            .filter(|route| !matches!(route, Route::Direct | Route::Proxy(_)))
            .map(ToString::to_string)
            .collect()
    }
}

fn host_name(text: &str) -> Result<String, GenerateError> {
    let bad = || GenerateError::BadHost(text.to_owned());
    let name = text.trim().to_ascii_lowercase();
    // "example.com." is the same name, and ".example.com" is how PAC scripts
    // write a domain: both are what is meant by the name without the dot.
    let name = name.trim_end_matches('.');
    let name = name.strip_prefix('.').unwrap_or(name);
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*' | '?'))
        && name.split('.').all(|label| !label.is_empty());
    if valid {
        Ok(name.to_owned())
    } else {
        Err(bad())
    }
}

/// A JavaScript string literal.
fn js_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The script `source`, unchanged, followed by the block of `rule`. `from` says
/// where the script came from, in a comment.
pub fn wrap(source: &[u8], rule: &Rule, from: &str) -> Vec<u8> {
    let mut out = source.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.push(b'\n');

    // The comment is one line, whatever the name of the file is.
    let from: String = from
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let mut block = String::new();
    let _ = writeln!(block, "// ===== gatir: local routes =====");
    let _ = writeln!(
        block,
        "// Generated by gatir {} from {from}.",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        block,
        "// The script above is the original, as it was. The hosts listed below get the\n\
         // proxies named; every other host is left to the original script."
    );
    let _ = writeln!(
        block,
        "// To add a host, add a name to a list. To add a rule, add an entry to `routes`.\n\
         // A name covers the domain and its sub-domains; * and ? stand for any text."
    );
    block.push_str("(function () {\n\tvar routes = [\n\t\t{\n\t\t\thosts: [\n");
    let names: Vec<String> = rule
        .hosts
        .iter()
        .map(|host| format!("\t\t\t\t{}", js_string(host)))
        .collect();
    block.push_str(&names.join(",\n"));
    let _ = write!(
        block,
        "\n\t\t\t],\n\t\t\tproxy: {}\n\t\t}}\n\t];\n",
        js_string(&rule.proxy)
    );
    block.push_str(
        r#"
	function listed(host, name) {
		if (name.indexOf("*") >= 0 || name.indexOf("?") >= 0) {
			return shExpMatch(host, name);
		}
		return host === name || host.slice(-(name.length + 1)) === "." + name;
	}

	function local(host) {
		host = String(host).toLowerCase();
		for (var i = 0; i < routes.length; i++) {
			for (var j = 0; j < routes[i].hosts.length; j++) {
				if (listed(host, routes[i].hosts[j])) {
					return routes[i].proxy;
				}
			}
		}
		return null;
	}

	function wrap(original) {
		return function (url, host) {
			return local(host) || original(url, host);
		};
	}

	if (typeof FindProxyForURL === "function") {
		FindProxyForURL = wrap(FindProxyForURL);
	}
	if (typeof FindProxyForURLEx === "function") {
		FindProxyForURLEx = wrap(FindProxyForURLEx);
	}
})();
// ===== end of gatir: local routes =====
"#,
    );
    out.extend_from_slice(block.as_bytes());
    out
}

/// A resolver that finds nothing: what is checked here never needs a lookup,
/// and nothing is to be sent anywhere.
#[derive(Debug)]
struct NoLookups;

impl Resolver for NoLookups {
    fn resolve(&self, _host: &str) -> Vec<std::net::IpAddr> {
        Vec::new()
    }

    fn local_addresses(&self) -> Vec<std::net::IpAddr> {
        Vec::new()
    }
}

/// The engine limits for a script that is only looked at: one engine will do.
pub fn tool_limits() -> PacLimits {
    PacLimits {
        workers: 1,
        ..PacLimits::default()
    }
}

/// Loads a script, as gatir would: bytes that are not UTF-8 are read as well as
/// they can be, since scripts written long ago are not always.
pub async fn load_script(script: &[u8], limits: PacLimits, env: PacEnv) -> Result<Pac, PacError> {
    let text = String::from_utf8_lossy(script).into_owned();
    tokio::task::spawn_blocking(move || Pac::load(&text, limits, env))
        .await
        .map_err(|err| PacError::Load(format!("the script could not be loaded: {err}")))?
}

/// Loads `script` and asks it about each host of `rule`: what comes out is the
/// answer of the rule, or the result is not what was meant. Returns each host
/// with what the script answered, for showing.
pub async fn check(script: &[u8], rule: &Rule) -> Result<Vec<(String, Vec<Route>)>, GenerateError> {
    let env = PacEnv::system(Arc::new(NoLookups));
    let pac = load_script(script, tool_limits(), env)
        .await
        .map_err(|err| GenerateError::Script(err.to_string()))?;

    let mut answers = Vec::new();
    for host in rule.hosts() {
        // A pattern is asked about a name it matches.
        let sample = host.replace('*', "www").replace('?', "a");
        let routes = pac
            .find(&format!("http://{sample}/"), &sample)
            .await
            .map_err(|err| GenerateError::Script(format!("asking about {sample}: {err}")))?;
        if routes != rule.routes() {
            return Err(GenerateError::Script(format!(
                "{sample} was answered {} and not {}",
                join(&routes),
                rule.proxy()
            )));
        }
        answers.push((host.clone(), routes));
    }
    Ok(answers)
}

fn join(routes: &[Route]) -> String {
    routes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(hosts: &[&str], proxy: &str) -> Rule {
        let hosts: Vec<String> = hosts.iter().map(|host| (*host).to_owned()).collect();
        Rule::new(&hosts, proxy).unwrap()
    }

    fn error(hosts: &[&str], proxy: &str) -> GenerateError {
        let hosts: Vec<String> = hosts.iter().map(|host| (*host).to_owned()).collect();
        Rule::new(&hosts, proxy).unwrap_err()
    }

    /// What `script` answers for `url`, as it would be written.
    async fn answer(script: &[u8], url: &str, host: &str) -> String {
        let env = PacEnv::system(Arc::new(NoLookups));
        let pac = load_script(script, tool_limits(), env).await.unwrap();
        join(&pac.find(url, host).await.unwrap())
    }

    const ORIGINAL: &str = "function FindProxyForURL(url, host) {\n\
                            \treturn \"PROXY original.example.com:3128\";\n}\n";

    #[test]
    fn names_are_lower_cased_and_without_the_dots_around_them() {
        let rule = rule(
            &["GHCR.io", ".githubusercontent.com", "crates.io.", "ghcr.io"],
            "PROXY a.example.com:80",
        );
        assert_eq!(
            rule.hosts(),
            ["ghcr.io", "githubusercontent.com", "crates.io"]
        );
    }

    #[test]
    fn what_is_not_a_host_name_is_refused() {
        for bad in [
            "",
            " ",
            "http://example.com",
            "example.com/path",
            "example.com:8080",
            "two words",
            "a..b",
            "user@example.com",
            "caf\u{e9}.example.com",
            "\"quoted\"",
            "a\nb",
            &"a".repeat(300),
        ] {
            assert!(
                matches!(error(&[bad], "DIRECT"), GenerateError::BadHost(_)),
                "{bad:?}"
            );
        }
        assert_eq!(error(&[], "DIRECT"), GenerateError::NoHosts);
        // Patterns are names, too.
        assert_eq!(
            rule(&["*.example.com", "a?.example.com"], "DIRECT")
                .hosts()
                .len(),
            2
        );
    }

    #[test]
    fn the_proxy_list_is_read_and_written_in_its_canonical_form() {
        let rule = rule(
            &["example.com"],
            "proxy  a.example.com;http b.example.com:8080 ;;direct",
        );
        assert_eq!(
            rule.proxy(),
            "PROXY a.example.com:80; PROXY b.example.com:8080; DIRECT"
        );
    }

    #[test]
    fn a_proxy_list_that_is_empty_or_has_a_bad_entry_is_refused() {
        assert_eq!(error(&["example.com"], ""), GenerateError::NoProxy);
        assert_eq!(error(&["example.com"], " ; "), GenerateError::NoProxy);
        assert_eq!(
            error(
                &["example.com"],
                "PROXY a.example.com:80; FTP b.example.com"
            ),
            GenerateError::BadProxy("FTP b.example.com".to_owned())
        );
        assert!(matches!(
            error(&["example.com"], "PROXY a.example.com:99999"),
            GenerateError::BadProxy(_)
        ));
        // Something a script could smuggle in is not a proxy.
        assert!(matches!(
            error(&["example.com"], "PROXY a\";alert(1);\""),
            GenerateError::BadProxy(_)
        ));
    }

    #[test]
    fn proxies_gatir_does_not_use_are_allowed_and_named() {
        let rule = rule(
            &["example.com"],
            "PROXY a.example.com:80; SOCKS5 b.example.com:1080",
        );
        assert_eq!(rule.unused(), ["SOCKS5 b.example.com:1080"]);
        assert!(self::rule(&["example.com"], "DIRECT").unused().is_empty());
    }

    #[test]
    fn the_script_is_kept_byte_for_byte() {
        // Not UTF-8, and no newline at the end.
        let mut source =
            b"// caf\xe9\nfunction FindProxyForURL(u, h) { return \"DIRECT\"; }".to_vec();
        let wrapped = wrap(&source, &rule(&["example.com"], "PROXY a:80"), "x.pac");
        assert!(wrapped.starts_with(&source));
        source.push(b'\n');
        let wrapped = wrap(&source, &rule(&["example.com"], "PROXY a:80"), "x.pac");
        assert!(wrapped.starts_with(&source));
        assert!(wrapped.ends_with(b"// ===== end of gatir: local routes =====\n"));
    }

    #[test]
    fn the_comment_stays_on_one_line_whatever_the_origin() {
        let wrapped = wrap(
            ORIGINAL.as_bytes(),
            &rule(&["example.com"], "DIRECT"),
            "http://h/p.pac\nalert(1)",
        );
        let text = String::from_utf8(wrapped).unwrap();
        assert!(text.contains("from http://h/p.pac?alert(1)."), "{text}");
        assert!(
            !text.lines().any(|line| line == "alert(1)"),
            "an injected line: {text}"
        );
    }

    #[tokio::test]
    async fn the_listed_hosts_get_the_proxies_and_the_others_the_original_answer() {
        let rule = rule(
            &["ghcr.io", "githubusercontent.com"],
            "PROXY a.example.com:80",
        );
        let script = wrap(ORIGINAL.as_bytes(), &rule, "x.pac");

        for (url, host) in [
            ("https://ghcr.io/", "ghcr.io"),
            (
                "https://pkg-containers.githubusercontent.com/x",
                "pkg-containers.githubusercontent.com",
            ),
            // Hosts are not case sensitive.
            ("https://GHCR.IO/", "GHCR.IO"),
        ] {
            assert_eq!(
                answer(&script, url, host).await,
                "PROXY a.example.com:80",
                "{host}"
            );
        }
        for (url, host) in [
            ("https://example.com/", "example.com"),
            // A name is a domain: not any host that ends with the same letters.
            ("https://notghcr.io/", "notghcr.io"),
            (
                "https://ghcr.io.evil.example.com/",
                "ghcr.io.evil.example.com",
            ),
        ] {
            assert_eq!(
                answer(&script, url, host).await,
                "PROXY original.example.com:3128",
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn patterns_use_shexpmatch() {
        let rule = rule(&["*.cdn.example.com", "app?.example.com"], "DIRECT");
        let script = wrap(ORIGINAL.as_bytes(), &rule, "x.pac");
        for host in ["a.cdn.example.com", "app1.example.com"] {
            assert_eq!(
                answer(&script, &format!("http://{host}/"), host).await,
                "DIRECT"
            );
        }
        for host in ["cdn.example.com", "app12.example.com"] {
            assert_eq!(
                answer(&script, &format!("http://{host}/"), host).await,
                "PROXY original.example.com:3128"
            );
        }
    }

    #[tokio::test]
    async fn every_way_of_writing_the_function_is_wrapped() {
        let rule = rule(&["ghcr.io"], "PROXY a.example.com:80");
        let shapes = [
            "var FindProxyForURL = function (url, host) { return \"PROXY o.example.com:1\"; };",
            "\"use strict\";\nfunction FindProxyForURL(url, host) { return \"PROXY o.example.com:1\"; }",
            "\u{feff}function FindProxyForURL(url, host) { return \"PROXY o.example.com:1\"; }",
            "function FindProxyForURL(url, host) { return \"PROXY o.example.com:1\"; }\r\n",
            "function FindProxyForURL(url, host) { return \"PROXY o.example.com:1\"; } // end",
        ];
        for shape in shapes {
            let script = wrap(shape.as_bytes(), &rule, "x.pac");
            assert_eq!(
                answer(&script, "https://ghcr.io/", "ghcr.io").await,
                "PROXY a.example.com:80",
                "{shape}"
            );
            assert_eq!(
                answer(&script, "https://other.example.com/", "other.example.com").await,
                "PROXY o.example.com:1",
                "{shape}"
            );
        }
    }

    #[tokio::test]
    async fn the_extended_function_is_wrapped_too() {
        // The engine asks FindProxyForURLEx first, when there is one.
        let original = "function FindProxyForURL(u, h) { return \"PROXY o.example.com:1\"; }\n\
                        function FindProxyForURLEx(u, h) { return \"PROXY ex.example.com:2\"; }\n";
        let script = wrap(
            original.as_bytes(),
            &rule(&["ghcr.io"], "PROXY a.example.com:80"),
            "x",
        );
        assert_eq!(
            answer(&script, "https://ghcr.io/", "ghcr.io").await,
            "PROXY a.example.com:80"
        );
        assert_eq!(
            answer(&script, "https://x.example.com/", "x.example.com").await,
            "PROXY ex.example.com:2"
        );
    }

    #[tokio::test]
    async fn rules_can_be_stacked_without_one_replacing_the_other() {
        let first = wrap(
            ORIGINAL.as_bytes(),
            &rule(&["one.example.com"], "PROXY a.example.com:80"),
            "x",
        );
        let both = wrap(
            &first,
            &rule(&["two.example.com"], "PROXY b.example.com:80"),
            "y",
        );
        for (host, expected) in [
            ("one.example.com", "PROXY a.example.com:80"),
            ("two.example.com", "PROXY b.example.com:80"),
            ("three.example.com", "PROXY original.example.com:3128"),
        ] {
            assert_eq!(
                answer(&both, &format!("http://{host}/"), host).await,
                expected
            );
        }
    }

    #[tokio::test]
    async fn the_check_asks_the_script_about_each_host() {
        let rule = rule(&["ghcr.io", "*.crates.io"], "PROXY a.example.com:80");
        let script = wrap(ORIGINAL.as_bytes(), &rule, "x.pac");
        let answers = check(&script, &rule).await.unwrap();
        assert_eq!(
            answers
                .iter()
                .map(|(host, _)| host.as_str())
                .collect::<Vec<_>>(),
            ["ghcr.io", "*.crates.io"]
        );
        assert!(answers.iter().all(|(_, routes)| routes == rule.routes()));
    }

    #[tokio::test]
    async fn a_script_that_does_not_work_is_refused() {
        let rule = rule(&["ghcr.io"], "DIRECT");
        for (name, source) in [
            ("no function", "var x = 1;\n"),
            (
                "syntax error",
                "function FindProxyForURL(url, host) { return \n",
            ),
            ("not a script", "this is just text\n"),
        ] {
            let script = wrap(source.as_bytes(), &rule, "x.pac");
            let result = check(&script, &rule).await;
            assert!(
                matches!(result, Err(GenerateError::Script(_))),
                "{name}: {result:?}"
            );
        }
        // A script that throws for the others is still fine: the rule answers first.
        let throws = "function FindProxyForURL(u, h) { throw new Error(\"boom\"); }\n";
        let script = wrap(throws.as_bytes(), &rule, "x.pac");
        assert!(check(&script, &rule).await.is_ok());
    }

    #[test]
    fn strings_are_written_so_that_they_cannot_end_early() {
        assert_eq!(js_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(js_string("a\nb"), "\"a\\u000ab\"");
    }
}
