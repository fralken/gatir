//! A check with a real Kerberos ticket, which automated runs do not have.
//!
//! It asks the system for a Negotiate token for a service and looks at what
//! comes back. Run it by hand, signed in with a valid ticket:
//!
//! ```sh
//! GATIR_TEST_SPN=HTTP@proxy.example.com cargo test --test kerberos_manual -- --ignored
//! ```

#![cfg(unix)]

use gatir::auth::system_tokens;

/// The DER of the SPNEGO mechanism identifier, 1.3.6.1.5.5.2.
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

#[test]
#[ignore = "needs a Kerberos ticket and GATIR_TEST_SPN"]
fn the_system_makes_a_spnego_token_from_the_ticket_of_the_user() {
    let Ok(service) = std::env::var("GATIR_TEST_SPN") else {
        panic!(
            "set GATIR_TEST_SPN to the service to ask a ticket for, like HTTP@proxy.example.com"
        );
    };

    let tokens = system_tokens().expect("the system has Kerberos");
    let token = tokens.token(&service).expect("a token for the service");

    // A GSS-API token starts with the application tag, and a SPNEGO one names
    // its mechanism.
    assert_eq!(token[0], 0x60, "not a GSS-API token");
    assert!(
        token
            .windows(SPNEGO_OID.len())
            .any(|part| part == SPNEGO_OID),
        "not a SPNEGO token"
    );
}
