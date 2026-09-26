//! Checks a PAC file against the results of another engine. Run by hand, on a
//! file that is not part of this repository:
//!
//! ```sh
//! node crates/gatir/tests/tools/pac-oracle.js proxy.pac cases.tsv > expected.tsv
//! GATIR_PAC=proxy.pac GATIR_PAC_EXPECTED=expected.tsv \
//!     cargo test --test pac_file -- --ignored --nocapture
//! ```
//!
//! `cases.tsv` has one `url<TAB>host` per line. The name lookups are fake and
//! the same in both, so that the comparison is about the script and the helper
//! functions and not about the network: a name has an address made from a hash
//! of it, and this machine is 10.10.10.10.

use std::net::IpAddr;
use std::sync::Arc;

use gatir::pac::{Pac, PacEnv, PacLimits, Resolver, parse};

/// FNV-1a over the lower-cased name, as in `tools/pac-oracle.js`.
fn fnv32(text: &str) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for byte in text.to_lowercase().bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

#[derive(Debug)]
struct Fake;

impl Resolver for Fake {
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return vec![address];
        }
        let hash = fnv32(host);
        let address = format!(
            "10.{}.{}.{}",
            (hash >> 8) & 255,
            (hash >> 16) & 255,
            1 + hash % 250
        );
        vec![address.parse().unwrap()]
    }

    fn local_addresses(&self) -> Vec<IpAddr> {
        vec!["10.10.10.10".parse().unwrap()]
    }
}

#[tokio::test]
#[ignore = "needs GATIR_PAC and GATIR_PAC_EXPECTED"]
async fn a_pac_file_gives_the_same_results_as_another_engine() {
    let (Ok(script), Ok(expected)) = (
        std::env::var("GATIR_PAC"),
        std::env::var("GATIR_PAC_EXPECTED"),
    ) else {
        panic!("set GATIR_PAC to the PAC file and GATIR_PAC_EXPECTED to the expected results");
    };
    let source = String::from_utf8_lossy(&std::fs::read(script).unwrap()).into_owned();
    let pac = Pac::load(
        &source,
        PacLimits::default(),
        PacEnv::system(Arc::new(Fake)),
    )
    .expect("the PAC file loads");

    let (mut checked, mut different) = (0usize, Vec::new());
    for line in std::fs::read_to_string(expected).unwrap().lines() {
        let mut fields = line.splitn(3, '\t');
        let (Some(url), Some(host), Some(result)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        checked += 1;
        let ours = pac.find(url, host).await;
        let agrees = match (&ours, result.strip_prefix("ERR ")) {
            (Err(_), Some(_)) => true,
            (Ok(routes), None) => *routes == parse(result).routes,
            _ => false,
        };
        if !agrees {
            different.push(format!(
                "{url}\n    ours:     {ours:?}\n    expected: {result}"
            ));
        }
    }
    println!("{checked} cases, {} different", different.len());
    for case in different.iter().take(10) {
        println!("{case}");
    }
    assert!(checked > 0, "no cases in the expected results");
    assert!(
        different.is_empty(),
        "{} of {checked} cases are different",
        different.len()
    );
}
