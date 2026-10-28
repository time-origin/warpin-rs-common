//! Validated TLS configuration using explicitly trusted CA certificates.
use crate::{Limits, tcp::Connection};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use warpin_errors::protocol::{Kind, Phase, ProtocolError, Result};
fn invalid() -> ProtocolError {
    ProtocolError::new(Kind::Configuration, Phase::Configure)
}
fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    if pem.is_empty() || pem.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if certs.is_empty() {
        return Err(invalid());
    }
    Ok(certs)
}
fn key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    if pem.is_empty() || pem.len() > 1024 * 1024 {
        return Err(invalid());
    }
    PrivateKeyDer::from_pem_slice(pem).map_err(|_| invalid())
}
/// Server identity. Fields intentionally have no Debug implementation.
pub struct Identity {
    /// Certificate chain in PEM format, leaf first; at most 1 MiB.
    pub certificate_pem: Vec<u8>,
    /// Private key PEM; treat as a secret and never log it.
    pub private_key_pem: Vec<u8>,
}
#[derive(Clone)]
pub struct ClientTls(Arc<rustls::ClientConfig>);
#[derive(Clone)]
pub struct ServerTls(TlsAcceptor);
impl ClientTls {
    /// Verified trust configuration, reusable by HTTP/MQTT clients.
    pub fn config(&self) -> Arc<rustls::ClientConfig> {
        self.0.clone()
    }
    /// Validates all required configuration before constructing local state.
    pub fn new(ca_pem: &[u8], identity: Option<&Identity>) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        for c in certificates(ca_pem)? {
            roots.add(c).map_err(|_| invalid())?;
        }
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?
        .with_root_certificates(roots);
        let config = match identity {
            Some(i) => builder
                .with_client_auth_cert(certificates(&i.certificate_pem)?, key(&i.private_key_pem)?)
                .map_err(|_| invalid())?,
            None => builder.with_no_client_auth(),
        };
        Ok(Self(Arc::new(config)))
    }
    /// Performs the validated connection/handshake within the configured deadline.
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        server_name: &str,
        limits: Limits,
    ) -> Result<Connection<tokio_rustls::client::TlsStream<S>>> {
        let limits = limits.validate()?;
        let name = ServerName::try_from(server_name.to_owned()).map_err(|_| invalid())?;
        let tls = timeout(
            limits.timeout,
            TlsConnector::from(self.0.clone()).connect(name, stream),
        )
        .await
        .map_err(|source| ProtocolError::new(Kind::Timeout, Phase::Connect).with_source(source))?
        .map_err(|source| {
            ProtocolError::new(Kind::Authentication, Phase::Connect).with_source(source)
        })?;
        Connection::new(tls, limits)
    }
}
impl ServerTls {
    /// If client_ca is supplied, client certificates are required.
    pub fn new(identity: &Identity, client_ca: Option<&[u8]>) -> Result<Self> {
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?;
        let builder = match client_ca {
            None => builder.with_no_client_auth(),
            Some(pem) => {
                let mut roots = rustls::RootCertStore::empty();
                for c in certificates(pem)? {
                    roots.add(c).map_err(|_| invalid())?;
                }
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
                )
                .build()
                .map_err(|_| invalid())?;
                builder.with_client_cert_verifier(verifier)
            }
        };
        let config = builder
            .with_single_cert(
                certificates(&identity.certificate_pem)?,
                key(&identity.private_key_pem)?,
            )
            .map_err(|_| invalid())?;
        Ok(Self(TlsAcceptor::from(Arc::new(config))))
    }
    /// Performs a server TLS handshake under the configured deadline.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        limits: Limits,
    ) -> Result<Connection<tokio_rustls::server::TlsStream<S>>> {
        let limits = limits.validate()?;
        let tls = timeout(limits.timeout, self.0.accept(stream))
            .await
            .map_err(|source| {
                ProtocolError::new(Kind::Timeout, Phase::Connect).with_source(source)
            })?
            .map_err(|source| {
                ProtocolError::new(Kind::Authentication, Phase::Connect).with_source(source)
            })?;
        Connection::new(tls, limits)
    }
}
