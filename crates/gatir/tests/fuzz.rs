//! The parsers of gatir, given inputs that are broken on purpose.
//!
//! Each test starts from inputs that are valid and changes them in thousands of
//! ways (see `gatir_testkit::fuzz`). What it asks is that the code neither
//! panics nor takes for ever, and that what it accepts is safe to use: an
//! address that comes out has a port, a secret is never shown, and what is
//! printed can be read back.
//!
//! `GATIR_FUZZ_SCALE=100 cargo test fuzz_` searches a hundred times as long.
//! A failure names the input that caused it, in hex.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use gatir::acl::Source;
use gatir::auth::ntlm::{Authenticator, Challenge};
use gatir::auth::{challenge, refusal};
use gatir::config::{Config, HostPort, Overrides, Tunnel};
use gatir::noproxy::NoProxy;
use gatir::pac::{self, Pac, PacEnv, PacError, PacLimits, Resolver, Route};
use gatir_testkit::fuzz::{each_text_variant, each_variant};
use hyper::header::HeaderValue;

// ---- NTLM ----

/// A CHALLENGE message (MS-NLMP 2.2.1.2) with `target_info` after the header.
fn type2(target_info: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"NTLMSSP\0");
    message.extend_from_slice(&2u32.to_le_bytes());
    message.extend_from_slice(&[0, 0, 0, 0]);
    message.extend_from_slice(&56u32.to_le_bytes());
    message.extend_from_slice(&0xe289_8215u32.to_le_bytes());
    message.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    message.extend_from_slice(&[0; 8]);
    let length = u16::try_from(target_info.len()).unwrap();
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(&56u32.to_le_bytes());
    message.extend_from_slice(&[6, 1, 0, 0, 0, 0, 0, 15]);
    message.extend_from_slice(target_info);
    message
}

/// The list of attribute-value pairs of a server: a name, its clock, the end.
fn av_pairs() -> Vec<u8> {
    let name: Vec<u8> = "CORP".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut pairs = Vec::new();
    pairs.extend_from_slice(&[2, 0]);
    pairs.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    pairs.extend_from_slice(&name);
    pairs.extend_from_slice(&[7, 0, 8, 0]);
    pairs.extend_from_slice(&0x01d9_0000_1234_5678u64.to_le_bytes());
    pairs.extend_from_slice(&[0, 0, 0, 0]);
    pairs
}

#[test]
fn fuzz_the_ntlm_challenge_message() {
    let full = type2(&av_pairs());
    let parsed = Challenge::parse(&full).expect("the seed is a challenge");
    assert_eq!(parsed.timestamp(), Some(0x01d9_0000_1234_5678));

    // An older server stops after the reserved field.
    let older = full[..32].to_vec();
    each_variant(&[&full, &type2(&[]), &older], 30_000, |message| {
        if let Ok(challenge) = Challenge::parse(message) {
            assert!(challenge.target_info.len() <= message.len());
            let _ = challenge.timestamp();
        }
    });
}

fn alice() -> Authenticator {
    let toml = "[credentials]\nusername = \"alice\"\ndomain = \"CORP\"\n\
                password = \"s3cret\"\nmethod = \"ntlmv2\"\n";
    let config = Config::from_toml_str(toml, Overrides::default()).unwrap();
    Authenticator::new(&config.credentials.unwrap()).unwrap()
}

#[test]
fn fuzz_answering_an_ntlm_challenge() {
    let alice = alice();
    let seed = type2(&av_pairs());

    // The message inside a well-formed field.
    each_variant(&[&seed, &type2(&[])], 3_000, |message| {
        let field = HeaderValue::try_from(format!("NTLM {}", STANDARD.encode(message))).unwrap();
        if let Ok(answer) = alice.respond(std::iter::once(&field)) {
            assert!(answer.to_str().unwrap().starts_with("NTLM "));
        }
    });

    // The field itself, as far as a header value can be broken.
    let valid = format!("NTLM {}", STANDARD.encode(&seed));
    each_variant(
        &[
            valid.as_bytes(),
            b"NTLM",
            b"Negotiate abc, NTLM TlRMTVNTUAAC",
        ],
        3_000,
        |text| {
            if let Ok(field) = HeaderValue::from_bytes(text) {
                let _ = alice.respond(std::iter::once(&field));
            }
        },
    );
}

#[test]
fn fuzz_the_proxy_authenticate_fields() {
    let seeds: [&[u8]; 6] = [
        b"Negotiate YIIBhgYGKwYBBQUC",
        b"NTLM TlRMTVNTUAACAAAA",
        b"Basic realm=\"a, b\", Negotiate",
        b"NEGOTIATE",
        b"NTLM",
        b"Digest realm=\"x\", nonce=\"y\", NTLM, Negotiate token==",
    ];
    each_variant(&seeds, 20_000, |text| {
        let Ok(field) = HeaderValue::from_bytes(text) else {
            return;
        };
        let two = [field.clone(), field];
        let _ = challenge(&two);
        let _ = refusal(&two);
        let _ = challenge(&two[..1]);
        let _ = refusal(&two[..1]);
    });
}

// ---- what is read from text ----

fn address_of(route: &Route) -> Option<&pac::ProxyAddr> {
    match route {
        Route::Direct => None,
        Route::Proxy(address)
        | Route::Https(address)
        | Route::Socks(address)
        | Route::Socks4(address)
        | Route::Socks5(address) => Some(address),
    }
}

#[test]
fn fuzz_the_result_of_a_pac_script() {
    let seeds = [
        "PROXY a.example.com:8080; PROXY b:3128; DIRECT",
        "SOCKS5 [::1]:1080; HTTPS proxy.example.com; socks4 10.0.0.1",
        "DIRECT",
        "PROXY 1.2.3.4",
    ];
    each_text_variant(&seeds, 20_000, |text| {
        let parsed = pac::parse(text);
        assert!(parsed.routes.len() + parsed.ignored.len() <= text.matches(';').count() + 1);
        for route in &parsed.routes {
            // What is printed can be read back as the same route.
            let again = pac::parse(&route.to_string());
            assert_eq!(again.routes, std::slice::from_ref(route), "{route}");
            assert!(again.ignored.is_empty(), "{route}");
            if let Some(address) = address_of(route) {
                assert_ne!(address.port, 0);
                assert!(!address.host.contains(char::is_whitespace), "{route}");
            }
        }
    });
}

#[test]
fn fuzz_a_host_and_port() {
    let seeds = [
        "proxy.example.com:8080",
        "[2001:db8::1]:3128",
        "10.0.0.1:1",
        "a_b-c.d:65535",
    ];
    each_text_variant(&seeds, 20_000, |text| {
        if let Ok(address) = text.parse::<HostPort>() {
            assert_ne!(address.port, 0);
            assert!(!address.host.is_empty());
            assert!(!address.host.contains(char::is_whitespace));
            assert_eq!(
                address.to_string().parse::<HostPort>().as_ref(),
                Ok(&address)
            );
            let _ = address.host_in_url();
        }
    });
}

#[test]
fn fuzz_a_tunnel() {
    let seeds = [
        "2222:git.example.com:22",
        "127.0.0.1:2222:git:22",
        "[::1]:2222:[2001:db8::1]:22",
        "*:8080:example.com:443",
        "localhost:2222:git:22",
    ];
    each_text_variant(&seeds, 20_000, |text| {
        if let Ok(tunnel) = text.parse::<Tunnel>() {
            assert_ne!(tunnel.listen.port(), 0);
            assert_ne!(tunnel.target.port, 0);
            assert!(!tunnel.target.host.contains(char::is_whitespace));
            let _ = tunnel.to_string();
        }
    });
}

#[test]
fn fuzz_the_source_of_an_access_rule() {
    let seeds = ["*", "10.0.0.0/8", "192.168.1.7", "2001:db8::/32", " ::1 "];
    each_text_variant(&seeds, 20_000, |text| {
        if let Ok(source) = text.parse::<Source>() {
            assert_eq!(source.to_string().parse::<Source>().as_ref(), Ok(&source));
        }
    });
}

#[test]
fn fuzz_a_no_proxy_pattern() {
    let seeds = [
        "*.internal.example.com",
        "10.0.0.0/8",
        "localhost",
        "[abc]*.example.{com,org}",
        "192.168.?.*",
        "2001:db8::1",
    ];
    each_text_variant(&seeds, 2_000, |text| {
        if let Ok(patterns) = NoProxy::new([text]) {
            for host in [text, "example.com", "10.1.2.3", "[::1]", "", "."] {
                let _ = patterns.matches(host);
            }
        }
    });
}

// ---- the configuration ----

const PASSWORD: &str = "PASSWORD-MARKER-1";
const SOCKS_PASSWORD: &str = "SOCKS-MARKER-2";
const HEADER_VALUE: &str = "HEADER-MARKER-3";

fn full_configuration() -> String {
    format!(
        r#"
listen = ["127.0.0.1:3128", "[::1]:3128"]
parents = ["proxy.example.com:8080", "[2001:db8::1]:3128"]
no_proxy = ["localhost", "10.0.0.0/8", "*.internal.example.com"]

[credentials]
method = "ntlmv2"
username = "alice"
domain = "EXAMPLE"
password = "{PASSWORD}"

[access]
default = "deny"
rules = [{{ allow = "127.0.0.1" }}, {{ allow = "192.168.0.0/16" }}, {{ deny = "*" }}]

[headers]
X-Example = "{HEADER_VALUE}"

[[tunnels]]
listen = "127.0.0.1:2222"
target = "git.example.com:22"

[socks5]
listen = ["127.0.0.1:1080"]
username = "bob"
password = "{SOCKS_PASSWORD}"

[timeouts]
connect_secs = 10
client_idle_secs = 60

[log]
level = "info"
"#
    )
}

#[test]
fn fuzz_the_configuration_and_never_show_a_secret() {
    let full = full_configuration();
    Config::from_toml_str(&full, Overrides::default()).expect("the seed is a configuration");
    let example = include_str!("../../../gatir.example.toml");
    Config::from_toml_str(example, Overrides::default()).expect("the example is a configuration");

    each_text_variant(&[&full, example], 2_000, |text| {
        let shown = match Config::from_toml_str(text, Overrides::default()) {
            Ok(config) => format!("{config:?}\n{}", config.summary()),
            Err(err) => format!("{err}\n{err:?}"),
        };
        for secret in [PASSWORD, SOCKS_PASSWORD, HEADER_VALUE] {
            assert!(!shown.contains(secret), "{secret} is shown: {shown}");
        }
    });
}

// ---- the PAC engine ----

#[derive(Debug)]
struct Resolves;

impl Resolver for Resolves {
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        if host.is_empty() {
            Vec::new()
        } else {
            vec![IpAddr::from([192, 0, 2, 1])]
        }
    }

    fn local_addresses(&self) -> Vec<IpAddr> {
        vec![IpAddr::from([192, 0, 2, 55])]
    }
}

fn environment() -> PacEnv {
    PacEnv {
        resolver: Arc::new(Resolves),
        clock: Arc::new(|| 1_700_000_000_000),
    }
}

/// Room for an honest script, even on a busy computer, and little for a bad one.
fn limits() -> PacLimits {
    PacLimits {
        time: Duration::from_millis(1500),
        memory: 8 * 1024 * 1024,
        stack: 256 * 1024,
        workers: 1,
        grace: Duration::from_millis(1000),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

/// A script that calls every helper with what it is given, and does not mind
/// what they do: a helper that throws must not take the script with it.
const EVERY_HELPER: &str = r#"
function FindProxyForURL(url, host) {
  var calls = [
    function () { return isPlainHostName(host); },
    function () { return dnsDomainIs(host, url); },
    function () { return localHostOrDomainIs(host, url); },
    function () { return dnsDomainLevels(host); },
    function () { return shExpMatch(url, host); },
    function () { return shExpMatch(host, url); },
    function () { return isInNet(host, url, host); },
    function () { return isInNetEx(host, url); },
    function () { return dnsResolve(host); },
    function () { return dnsResolveEx(host); },
    function () { return isResolvable(host); },
    function () { return isResolvableEx(host); },
    function () { return myIpAddress(); },
    function () { return myIpAddressEx(); },
    function () { return sortIpAddressList(host); },
    function () { return weekdayRange(host, url); },
    function () { return dateRange(host, url, host); },
    function () { return timeRange(host, url, host, url); }
  ];
  for (var i = 0; i < calls.length; i++) { try { calls[i](); } catch (e) {} }
  return "PROXY " + host + ":8080; DIRECT";
}
"#;

/// What must never come of a script that loaded and was asked a plain question:
/// the engine gone, or given up on.
fn assert_engine_alive(result: &Result<Vec<Route>, PacError>, what: &str) {
    if let Err(err @ (PacError::Unavailable | PacError::Broken)) = result {
        panic!("{what}: the engine is no longer running: {err}");
    }
}

#[test]
fn fuzz_what_a_pac_script_is_asked() {
    let pac = Pac::load(EVERY_HELPER, limits(), environment()).expect("the script loads");
    let runtime = runtime();
    let seeds = [
        "http://www.example.com/path?q=1|www.example.com",
        "https://[2001:db8::1]:8443/|2001:db8::1",
        "ftp://a.b.c/|a.b.c",
        "http://10.1.2.3/x|10.1.2.3",
        "http://localhost/|localhost",
        "http://*.example.{com,org}/|a[bc]?.example.com",
    ];
    each_text_variant(&seeds, 1_500, |text| {
        let (url, host) = text.split_once('|').unwrap_or((text, text));
        let result = runtime.block_on(pac.find(url, host));
        assert_engine_alive(&result, "a question");
        // The script is quick, and every question is small: a limit that is
        // reached says a helper takes too long over some input.
        assert!(
            !matches!(result, Err(PacError::Timeout(_))),
            "a helper is too slow over url {url:?} and host {host:?}"
        );
    });
}

#[test]
fn fuzz_a_pac_script_that_is_broken() {
    let seed = "function FindProxyForURL(url, host) {\n  if (isPlainHostName(host)) return \"DIRECT\";\n  \
                return \"PROXY a:80\";\n}\n";
    let runtime = runtime();
    each_variant(&[seed.as_bytes()], 100, |script| {
        let script = String::from_utf8_lossy(script);
        // A script that does not compile, or has no `FindProxyForURL`, is an
        // error to report; one that loads is asked, and may run out of time.
        if let Ok(pac) = Pac::load(&script, limits(), environment()) {
            let result = runtime.block_on(pac.find("http://www.example.com/", "www.example.com"));
            assert_engine_alive(&result, "a broken script");
        }
    });
}
