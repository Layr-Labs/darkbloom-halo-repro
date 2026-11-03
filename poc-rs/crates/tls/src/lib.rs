//! TLS for the coordinator, the provider agent and the consumer.
//!
//! - rustls with the *ring* provider only. [`install_default_provider`]
//!   makes it the process default (every binary calls it at startup), and
//!   every configuration here is built with it explicitly, so nothing
//!   depends on which provider happens to be installed. No aws-lc.
//! - TLS 1.3 only, ALPN `http/1.1` (the provider WebSocket is an HTTP/1.1
//!   upgrade; HTTP/2 is not served).
//! - Clients trust either a pinned CA bundle (`-ca-cert`: those certificates
//!   are the only anchors) or Mozilla's root program (webpki-roots), never
//!   the platform store.
//! - [`check_listen`]: the coordinator serves plain HTTP only on loopback
//!   unless explicitly told otherwise.
//! - [`devcert`]: development certificates (a P-256 CA and a server
//!   certificate), built in pure Rust.

#![forbid(unsafe_code)]

pub mod devcert;

pub use rustls;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

/// TLS configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A certificate or key file could not be used.
    #[error("tls: {path}: {msg}")]
    File {
        /// The file.
        path: String,
        /// What is wrong with it.
        msg: String,
    },
    /// Anything else.
    #[error("tls: {0}")]
    Invalid(String),
}

impl Error {
    fn file(path: &Path, msg: impl std::fmt::Display) -> Self {
        Self::File { path: path.display().to_string(), msg: msg.to_string() }
    }

    fn invalid(msg: impl std::fmt::Display) -> Self {
        Self::Invalid(msg.to_string())
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// The only protocol version offered or accepted.
pub static PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// The only application protocol (ALPN) offered or accepted.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// The crypto provider every configuration uses: ring.
pub fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())).clone()
}

/// Installs ring as the process-wide default rustls provider. Idempotent; a
/// provider installed earlier is kept. Binaries call this first.
pub fn install_default_provider() {
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

/// Trust anchors for a TLS client.
#[derive(Debug, Clone)]
pub enum Trust {
    /// Mozilla's root program (webpki-roots): a coordinator with a publicly
    /// trusted certificate.
    WebPki,
    /// Only these certificates (a pinned CA bundle). Empty trusts nothing.
    Pinned(Vec<CertificateDer<'static>>),
}

impl Trust {
    /// The certificates of a PEM bundle as the only anchors, or Mozilla's
    /// roots without one.
    pub fn from_ca_file(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => Ok(Self::Pinned(load_certificates(p)?)),
            None => Ok(Self::WebPki),
        }
    }
}

/// Reads every certificate of a PEM file; at least one is required.
pub fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::file(path, e))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::file(path, e))?;
    if certs.is_empty() {
        return Err(Error::file(path, "no PEM certificate"));
    }
    Ok(certs)
}

/// A TLS 1.3 client configuration with the given anchors.
pub fn client_config(trust: &Trust) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    match trust {
        Trust::WebPki => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        Trust::Pinned(certs) => {
            for c in certs {
                roots.add(c.clone()).map_err(|e| Error::invalid(format!("CA certificate: {e}")))?;
            }
        }
    }
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .map_err(Error::invalid)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Ok(cfg)
}

/// [`client_config`] for an optional `-ca-cert` file.
pub fn client_config_for(ca_file: Option<&Path>) -> Result<ClientConfig> {
    client_config(&Trust::from_ca_file(ca_file)?)
}

/// A TLS 1.3 server configuration from a PEM certificate chain (leaf first)
/// and its private key (PKCS#8, SEC1 or PKCS#1 PEM). A key that does not
/// match the certificate is refused.
pub fn server_config(cert_file: &Path, key_file: &Path) -> Result<ServerConfig> {
    let chain = load_certificates(cert_file)?;
    let key = PrivateKeyDer::from_pem_file(key_file).map_err(|e| Error::file(key_file, e))?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .map_err(Error::invalid)?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| Error::file(cert_file, e))?;
    cfg.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Ok(cfg)
}

/// How the coordinator listens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listen {
    /// HTTPS, with WSS for providers.
    Tls,
    /// Plain HTTP on a loopback address (an SSH tunnel or a local proxy is in
    /// front).
    PlainLoopback,
    /// Plain HTTP on a reachable address, explicitly allowed
    /// (`-insecure-plain-http`, e.g. behind a TLS-terminating proxy).
    PlainExposed,
}

/// Whether `listen` (`host:port`) names only loopback: `localhost` or a
/// loopback IP address. An empty host means every interface.
pub fn is_loopback_listen(listen: &str) -> bool {
    let host = match listen.strip_prefix('[') {
        Some(rest) => rest.split_once("]:").map(|(h, _)| h),
        None => listen.rsplit_once(':').map(|(h, _)| h),
    };
    match host {
        None | Some("") => false,
        Some(h) if h.eq_ignore_ascii_case("localhost") => true,
        Some(h) => h.parse::<IpAddr>().is_ok_and(|ip| ip.to_canonical().is_loopback()),
    }
}

/// The coordinator's listen policy: plain HTTP only on loopback unless
/// `insecure_plain_http`. Prompts reach the coordinator in plaintext by
/// design and providers authenticate the coordinator over this connection,
/// so anything reachable from the network needs TLS.
pub fn check_listen(listen: &str, tls: bool, insecure_plain_http: bool) -> std::result::Result<Listen, String> {
    if tls && insecure_plain_http {
        return Err("-insecure-plain-http contradicts -tls-cert/-tls-key".to_owned());
    }
    if tls {
        return Ok(Listen::Tls);
    }
    if is_loopback_listen(listen) {
        return Ok(Listen::PlainLoopback);
    }
    if insecure_plain_http {
        return Ok(Listen::PlainExposed);
    }
    Err(format!(
        "refusing to serve plain HTTP on {listen:?}, which is not a loopback address: consumers send prompts to the coordinator \
         and providers authenticate it over this connection. Pass -tls-cert and -tls-key (dbcoord devcert makes a development \
         certificate), or -insecure-plain-http if a TLS-terminating proxy is in front"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn loopback_listen_addresses() {
        for a in ["127.0.0.1:8787", "127.1.2.3:1", "localhost:8787", "LOCALHOST:1", "[::1]:8787", "[::ffff:127.0.0.1]:8787"] {
            assert!(is_loopback_listen(a), "{a}");
        }
        for a in [":8787", "0.0.0.0:8787", "[::]:8787", "100.64.0.1:8787", "example.com:8787", "127.0.0.1", "", "[::1]", "10.0.0.1:443"] {
            assert!(!is_loopback_listen(a), "{a}");
        }
    }

    #[test]
    fn plain_http_only_on_loopback_unless_insecure() {
        assert_eq!(check_listen("127.0.0.1:8787", false, false), Ok(Listen::PlainLoopback));
        assert_eq!(check_listen("0.0.0.0:8787", true, false), Ok(Listen::Tls));
        assert_eq!(check_listen("127.0.0.1:8787", true, false), Ok(Listen::Tls));
        assert_eq!(check_listen("0.0.0.0:8787", false, true), Ok(Listen::PlainExposed));
        for a in ["0.0.0.0:8787", ":8787", "100.64.0.1:8787", "[::]:8787"] {
            let err = check_listen(a, false, false).unwrap_err();
            assert!(err.contains("refusing to serve plain HTTP") && err.contains("-insecure-plain-http"), "{a}: {err}");
        }
        assert!(check_listen("0.0.0.0:8787", true, true).unwrap_err().contains("contradicts"));
    }

    #[test]
    fn webpki_and_pinned_client_configs() {
        let cfg = client_config(&Trust::WebPki).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let nothing = client_config(&Trust::Pinned(Vec::new())).unwrap();
        assert!(nothing.alpn_protocols.len() == 1);
        let garbage = Trust::Pinned(vec![CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01])]);
        assert!(client_config(&garbage).is_err(), "a non-certificate was accepted as an anchor");
    }

    #[test]
    fn missing_or_empty_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        let err = load_certificates(&empty).unwrap_err().to_string();
        assert!(err.contains("no PEM certificate"), "{err}");
        assert!(load_certificates(&dir.path().join("missing.pem")).is_err());
        assert!(client_config_for(Some(&empty)).is_err());
        assert!(server_config(&empty, &empty).is_err());
    }
}
