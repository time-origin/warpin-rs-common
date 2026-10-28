//! Native TLS avoids rumqttc 0.25's obsolete rustls-webpki dependency.
//! All trust roots and optional identity are explicit. No insecure verifier switch.
use crate::error;
use native_tls::{Certificate, Identity as NativeIdentity, TlsConnector};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use warpin_errors::protocol::{Kind, Phase, Result};
use warpin_transport::tls::{ClientTls, Identity};
/// Validated native trust policy. Intentionally no Debug or raw connector getter.
#[derive(Clone)]
pub struct MqttTls(TlsConnector);
impl MqttTls {
    /// Identity private key must be PKCS#8 PEM (BEGIN PRIVATE KEY).
    pub fn new(ca_pem: &[u8], identity: Option<&Identity>) -> Result<Self> {
        // Reuse size/PEM/CA/private-key validation from the shared TLS module.
        ClientTls::new(ca_pem, identity)?;
        let invalid = || error(Kind::Configuration, Phase::Configure);
        let mut builder = TlsConnector::builder();
        builder
            .disable_built_in_roots(true)
            .min_protocol_version(Some(native_tls::Protocol::Tlsv12));
        for cert in CertificateDer::pem_slice_iter(ca_pem) {
            let cert = cert.map_err(|e| invalid().with_source(e))?;
            builder.add_root_certificate(
                Certificate::from_der(&cert).map_err(|e| invalid().with_source(e))?,
            );
        }
        if let Some(id) = identity {
            builder.identity(
                NativeIdentity::from_pkcs8(&id.certificate_pem, &id.private_key_pem)
                    .map_err(|e| invalid().with_source(e))?,
            );
        }
        Ok(Self(builder.build().map_err(|e| invalid().with_source(e))?))
    }
    pub(crate) fn connector(&self) -> TlsConnector {
        self.0.clone()
    }
}
