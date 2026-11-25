//! Optional HTTPS listener with OAuth mutual TLS (RFC 8705, ADR 0017).
//!
//! The server asks every client for a certificate but does not require one,
//! so browsers and public clients still connect. A presented certificate is
//! not chain-validated: RFC 8705 §2.2 self-signed client authentication
//! compares the certificate itself with the one the client registered, and
//! certificate-bound tokens only need the thumbprint. rustls still verifies
//! the handshake signature, so a client proves it holds the private key.
//!
//! [`serve_tls`] inserts the leaf certificate as a [`TlsClientCert`] request
//! extension for each connection, and adds `Strict-Transport-Security` to
//! every HTTPS response (RFC 6797; never sent over plain HTTP).

use std::sync::Arc;

use axum::http::{header, HeaderValue};
use axum::response::Response;
use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{Https, TlsClientCert};

/// Accepts any client certificate whose handshake signature verifies.
#[derive(Debug)]
struct AnyClientCert {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Identity is decided by the AS from the certificate thumbprint.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// rustls server configuration with optional, self-signed client certificates.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(AnyClientCert {
        provider: provider.clone(),
    });
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Loads a PEM certificate chain and private key into [`server_config`].
pub fn server_config_from_pem_files(
    cert_path: &str,
    key_path: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    use rustls_pki_types::pem::PemObject;
    let certs = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    Ok(server_config(certs, key)?)
}

/// Reads DER certificates from a PEM file (for `tls_client_auth` CAs).
pub fn ders_from_pem_file(path: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    use rustls_pki_types::pem::PemObject;
    Ok(CertificateDer::pem_file_iter(path)?
        .map(|c| c.map(|c| c.as_ref().to_vec()))
        .collect::<Result<Vec<_>, _>>()?)
}

/// HSTS value: one year, as RFC 6797 §11.2 suggests for established sites.
pub const HSTS: &str = "max-age=31536000";

async fn add_hsts(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static(HSTS));
    res
}

/// Serves `router` over TLS, tagging each request with the connection's
/// client certificate. Runs until the listener fails.
pub async fn serve_tls(
    listener: TcpListener,
    router: Router,
    config: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    let router = router.layer(axum::middleware::map_response(add_hsts));
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("TLS handshake failed: {e}");
                    return;
                }
            };
            let cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|c| c.as_ref().to_vec());
            let service = TowerToHyperService::new(
                router
                    .layer(Extension(TlsClientCert(cert)))
                    .layer(Extension(Https)),
            );
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!("connection error: {e}");
            }
        });
    }
}
