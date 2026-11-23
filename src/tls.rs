use std::io;
use std::sync::Arc;

use rustls_pki_types::pem::{self, PemObject};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{crypto::ring, ServerConfig};
use tokio_rustls::TlsAcceptor;

use crate::config::Server;

// Map a PEM parsing error to an io::Error that mentions the filename.
fn pem_error(filename: &str, e: pem::Error, what: &str) -> io::Error {
    match e {
        pem::Error::Io(e) => io::Error::new(e.kind(), format!("{}: {}", filename, e)),
        pem::Error::NoItemsFound => {
            io::Error::new(io::ErrorKind::InvalidData, format!("{}: expected {}", filename, what))
        },
        _ => io::Error::new(io::ErrorKind::InvalidData, format!("{}: invalid data", filename)),
    }
}

pub fn tls_acceptor(cfg: &Server) -> io::Result<TlsAcceptor> {
    // Private key (PKCS#1 RSA, SEC1 EC, or PKCS#8).
    let pkey_fn = cfg.tls_key.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "config: server: tls_key not set")
    })?;
    let pkey = PrivateKeyDer::from_pem_file(pkey_fn).map_err(|e| pem_error(pkey_fn, e, "one private key"))?;

    // Certificate chain.
    let cert_fn = cfg.tls_cert.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "config: server: tls_cert not set")
    })?;
    let certs = CertificateDer::pem_file_iter(cert_fn)
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
        .map_err(|e| pem_error(cert_fn, e, "at least one certificate"))?;

    let tls_err = |e: tokio_rustls::rustls::Error| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}/{}: {}", pkey_fn, cert_fn, e))
    };
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(tls_err)?
        .with_no_client_auth()
        .with_single_cert(certs, pkey)
        .map_err(tls_err)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
