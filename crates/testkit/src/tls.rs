//! Certificates made on the spot, and a TLS server to present them.
//!
//! The server is rustls, on purpose: the code under test talks TLS through the
//! operating system, and a peer built on another implementation is a check
//! that does not share its mistakes. Nothing here reaches the shipped binary.
//!
//! The certificates last a month, not a century: macOS refuses a server
//! certificate valid for more than 398 days when it chains to an authority it
//! was told about, so a fixture that lasts would not be accepted, and one that
//! is accepted would expire in the repository.

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};
use tokio_rustls::TlsAcceptor;

/// A certificate authority that exists for one test.
pub struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

/// A server certificate and its key.
pub struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl TestCa {
    pub fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::default()).expect("no names to check");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        (params.not_before, params.not_after) = window(-1, 30);
        let key = KeyPair::generate().expect("a key for the authority");
        let certificate = params
            .self_signed(&key)
            .expect("the authority's certificate");
        Self {
            pem: certificate.pem(),
            issuer: Issuer::new(params, key),
        }
    }

    /// The certificate to trust, as PEM.
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// A certificate valid now for `names`: DNS names, or IP addresses.
    pub fn server(&self, names: &[&str]) -> Identity {
        self.issue(names, window(-1, 30))
    }

    /// A certificate for `names` that ran out a week ago.
    pub fn expired_server(&self, names: &[&str]) -> Identity {
        self.issue(names, window(-30, -7))
    }

    fn issue(&self, names: &[&str], (from, until): (OffsetDateTime, OffsetDateTime)) -> Identity {
        let mut params = CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("names a certificate can carry");
        params
            .distinguished_name
            .push(DnType::CommonName, names.first().copied().unwrap_or("test"));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        (params.not_before, params.not_after) = (from, until);
        let key = KeyPair::generate().expect("a key for the server");
        let certificate = params
            .signed_by(&key, &self.issuer)
            .expect("the server's certificate");
        Identity {
            certificate: certificate.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()),
        }
    }
}

/// From `from_days` to `until_days` counted from now; negative is the past.
fn window(from_days: i64, until_days: i64) -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (
        now + Duration::days(from_days),
        now + Duration::days(until_days),
    )
}

impl Identity {
    pub(crate) fn acceptor(&self) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions the provider supports")
            .with_no_client_auth()
            .with_single_cert(
                vec![self.certificate.clone()],
                PrivateKeyDer::Pkcs8(self.key.clone_key()),
            )
            .expect("a certificate that matches its key");
        TlsAcceptor::from(Arc::new(config))
    }
}
