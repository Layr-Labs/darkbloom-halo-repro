//! Development certificates and the TLS configurations: certificate
//! contents, chain and name verification with rustls's verifier, and real
//! in-memory handshakes (TLS 1.3 only, ALPN http/1.1, pinned anchors).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_tls::devcert::{self, CA_FILE, CERT_FILE, KEY_FILE};
use db_tls::rustls::{self, ClientConnection, ServerConnection};
use db_tls::{Trust, client_config, client_config_for, load_certificates, server_config};
use der::Decode as _;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::ServerName;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};

fn cert_der(path: &Path) -> Vec<u8> {
    load_certificates(path).unwrap().remove(0).to_vec()
}

fn days(a: SystemTime, b: SystemTime) -> u64 {
    b.duration_since(a).unwrap().as_secs() / 86_400
}

#[test]
fn devcert_files_and_extensions() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("tls");
    let dc = devcert::write(&dir, &["127.0.0.1", " localhost ", "", "100.64.0.1", "[::1]", "coord.example"]).unwrap();
    assert_eq!(dc.hosts, ["127.0.0.1", "localhost", "100.64.0.1", "[::1]", "coord.example"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |f: &str| std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(KEY_FILE), 0o600);
        assert_eq!(mode(CERT_FILE), 0o644);
        assert_eq!(mode(CA_FILE), 0o644);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    }
    let key = std::fs::read_to_string(dir.join(KEY_FILE)).unwrap();
    assert!(key.starts_with("-----BEGIN PRIVATE KEY-----\n"), "not PKCS#8 PEM: {key}");

    let ca = Certificate::from_der(&cert_der(&dir.join(CA_FILE))).unwrap();
    let leaf = Certificate::from_der(&cert_der(&dir.join(CERT_FILE))).unwrap();
    let (ca_tbs, leaf_tbs) = (ca.tbs_certificate(), leaf.tbs_certificate());
    assert_eq!(ca_tbs.issuer(), ca_tbs.subject(), "CA is not self-signed");
    assert_eq!(leaf_tbs.issuer(), ca_tbs.subject());
    let (crit, bc) = ca_tbs.get_extension::<BasicConstraints>().unwrap().unwrap();
    assert!(crit && bc.ca);
    let (_, ku) = ca_tbs.get_extension::<KeyUsage>().unwrap().unwrap();
    assert!(ku.0.contains(KeyUsages::KeyCertSign));
    let (_, bc) = leaf_tbs.get_extension::<BasicConstraints>().unwrap().unwrap();
    assert!(!bc.ca);
    let (_, eku) = leaf_tbs.get_extension::<ExtendedKeyUsage>().unwrap().unwrap();
    assert_eq!(eku.0, vec![const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")]);
    let (_, san) = leaf_tbs.get_extension::<SubjectAltName>().unwrap().unwrap();
    let ips = san.0.iter().filter(|n| matches!(n, GeneralName::IpAddress(_))).count();
    let dns = san.0.iter().filter(|n| matches!(n, GeneralName::DnsName(_))).count();
    assert_eq!((ips, dns), (3, 2), "{san:?}");
    let validity =
        |t: &x509_cert::certificate::TbsCertificate| (t.validity().not_before.to_system_time(), t.validity().not_after.to_system_time());
    let (nb, na) = validity(ca_tbs);
    assert!(nb < SystemTime::now() && (364..=366).contains(&days(nb, na)), "CA validity");
    let (nb, na) = validity(leaf_tbs);
    assert!(nb < SystemTime::now() && (89..=91).contains(&days(nb, na)), "server validity");
    assert!(dc.not_after > SystemTime::now() + Duration::from_secs(89 * 86_400));
}

#[test]
fn bad_hosts_are_refused() {
    assert!(devcert::generate::<&str>(&[]).is_err());
    assert!(devcert::generate(&["", " "]).is_err());
    let err = devcert::generate(&["127.0.0.1", "not a host!"]).unwrap_err().to_string();
    assert!(err.contains("neither an IP address nor a DNS name"), "{err}");
}

/// rustls's own verifier accepts the server certificate for exactly its
/// names, under the pinned CA only.
#[test]
fn verifier_accepts_exactly_the_certified_names() {
    let tmp = tempfile::tempdir().unwrap();
    devcert::write(tmp.path(), &["127.0.0.1", "localhost", "100.64.0.1"]).unwrap();
    let other = tempfile::tempdir().unwrap();
    devcert::write(other.path(), &["127.0.0.1"]).unwrap();
    let leaf = rustls::pki_types::CertificateDer::from(cert_der(&tmp.path().join(CERT_FILE)));
    let verifier = |ca: &Path| {
        let mut roots = rustls::RootCertStore::empty();
        for c in load_certificates(ca).unwrap() {
            roots.add(c).unwrap();
        }
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), db_tls::provider()).build().unwrap()
    };
    let now = rustls::pki_types::UnixTime::now();
    let good = verifier(&tmp.path().join(CA_FILE));
    for name in ["127.0.0.1", "localhost", "100.64.0.1"] {
        let sn = ServerName::try_from(name).unwrap();
        good.verify_server_cert(&leaf, &[], &sn, &[], now).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    for name in ["example.com", "10.0.0.1", "127.0.0.2"] {
        let sn = ServerName::try_from(name).unwrap();
        assert!(good.verify_server_cert(&leaf, &[], &sn, &[], now).is_err(), "{name} accepted");
    }
    let wrong = verifier(&other.path().join(CA_FILE));
    let sn = ServerName::try_from("127.0.0.1").unwrap();
    let err = wrong.verify_server_cert(&leaf, &[], &sn, &[], now).unwrap_err();
    assert!(err.to_string().contains("UnknownIssuer"), "{err}");
}

/// Runs a handshake between two in-memory connections.
fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), rustls::Error> {
    for _ in 0..20 {
        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            server.read_tls(&mut buf.as_slice()).unwrap();
            server.process_new_packets()?;
        }
        let mut buf = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            client.read_tls(&mut buf.as_slice()).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not finish");
}

fn connect(
    client_cfg: rustls::ClientConfig,
    server_cfg: &Arc<rustls::ServerConfig>,
    name: &str,
) -> Result<ClientConnection, rustls::Error> {
    let mut client = ClientConnection::new(Arc::new(client_cfg), ServerName::try_from(name.to_owned()).unwrap()).unwrap();
    let mut server = ServerConnection::new(server_cfg.clone()).unwrap();
    handshake(&mut client, &mut server).map(|()| client)
}

#[test]
fn tls13_handshakes_with_pinned_anchors_only() {
    let tmp = tempfile::tempdir().unwrap();
    devcert::write(tmp.path(), &["127.0.0.1", "localhost"]).unwrap();
    let other = tempfile::tempdir().unwrap();
    devcert::write(other.path(), &["127.0.0.1", "localhost"]).unwrap();
    let server = Arc::new(server_config(&tmp.path().join(CERT_FILE), &tmp.path().join(KEY_FILE)).unwrap());

    let pinned = client_config_for(Some(&tmp.path().join(CA_FILE))).unwrap();
    let c = connect(pinned.clone(), &server, "localhost").unwrap();
    assert_eq!(c.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(c.alpn_protocol(), Some(&b"http/1.1"[..]));
    connect(pinned.clone(), &server, "127.0.0.1").unwrap();
    // The certificate does not cover this name.
    assert!(connect(pinned, &server, "coord.example").is_err());
    // Pinned to another CA, or trusting only Mozilla's roots: refused.
    for trust in [Trust::from_ca_file(Some(&other.path().join(CA_FILE))).unwrap(), Trust::WebPki, Trust::Pinned(Vec::new())] {
        let err = connect(client_config(&trust).unwrap(), &server, "localhost").unwrap_err();
        assert!(err.to_string().contains("UnknownIssuer"), "{err}");
    }
    // A TLS 1.2-only client finds no common version.
    let tls12 = rustls::ClientConfig::builder_with_provider(db_tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    assert!(connect(tls12, &server, "localhost").is_err(), "TLS 1.2 accepted");
    // A client that insists on HTTP/2 is refused (ALPN).
    let mut h2 = client_config_for(Some(&tmp.path().join(CA_FILE))).unwrap();
    h2.alpn_protocols = vec![b"h2".to_vec()];
    assert!(connect(h2, &server, "localhost").is_err(), "h2-only ALPN accepted");
}

#[test]
fn server_refuses_a_key_from_another_certificate() {
    let tmp = tempfile::tempdir().unwrap();
    devcert::write(tmp.path(), &["127.0.0.1"]).unwrap();
    let other = tempfile::tempdir().unwrap();
    devcert::write(other.path(), &["127.0.0.1"]).unwrap();
    let err = server_config(&tmp.path().join(CERT_FILE), &other.path().join(KEY_FILE)).unwrap_err().to_string();
    assert!(err.contains(CERT_FILE), "{err}");
    let err = server_config(&tmp.path().join(CERT_FILE), &tmp.path().join("missing.key")).unwrap_err().to_string();
    assert!(err.contains("missing.key"), "{err}");
}
