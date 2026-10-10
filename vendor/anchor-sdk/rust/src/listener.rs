use std::{net::SocketAddr, sync::Arc};

use rustls::{
    DigitallySignedStruct, SignatureScheme,
    pki_types::{CertificateDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use thiserror::Error;

use crate::{AcceptedSession, Session, SessionError, SessionIdentity, quinn_transport};

#[derive(Clone, Debug)]
pub struct ListenerIdentity {
    certificate_pem: String,
    private_key_pem: String,
}

impl ListenerIdentity {
    pub fn from_pem(
        certificate_pem: impl Into<String>,
        private_key_pem: impl Into<String>,
    ) -> Self {
        Self {
            certificate_pem: certificate_pem.into(),
            private_key_pem: private_key_pem.into(),
        }
    }

    pub fn certificate_der(&self) -> Result<Vec<u8>, ListenerError> {
        let mut certificate_pem = self.certificate_pem.as_bytes();
        rustls_pemfile::certs(&mut certificate_pem)
            .next()
            .transpose()
            .map_err(|_| ListenerError::InvalidIdentity("certificate PEM is invalid"))?
            .map(|certificate| certificate.as_ref().to_vec())
            .ok_or(ListenerError::InvalidIdentity("certificate PEM is empty"))
    }

    fn server_config(&self) -> Result<rustls::ServerConfig, ListenerError> {
        let mut certificate_pem = self.certificate_pem.as_bytes();
        let certificates = rustls_pemfile::certs(&mut certificate_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ListenerError::InvalidIdentity("certificate PEM is invalid"))?;
        let mut private_key_pem = self.private_key_pem.as_bytes();
        let private_key = rustls_pemfile::private_key(&mut private_key_pem)
            .map_err(|_| ListenerError::InvalidIdentity("private key PEM is invalid"))?
            .ok_or(ListenerError::InvalidIdentity("private key PEM is empty"))?;
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(AcceptAnyClientCertificate::new()))
            .with_single_cert(certificates, private_key)
            .map_err(|_| ListenerError::InvalidIdentity("certificate and private key do not match"))
    }
}

#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub bind_address: SocketAddr,
    pub identity: ListenerIdentity,
    pub session_identity: SessionIdentity,
}

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("Anchor listener identity is invalid: {0}")]
    InvalidIdentity(&'static str),
    #[error("failed to configure Anchor QUIC listener")]
    TransportConfiguration,
    #[error("failed to bind Anchor listener: {0}")]
    Bind(#[source] std::io::Error),
    #[error(transparent)]
    Session(#[from] SessionError),
}

pub struct IncomingConnection {
    incoming: quinn::Incoming,
    session_identity: SessionIdentity,
}

impl IncomingConnection {
    pub async fn accept(self) -> Result<AcceptedSession, ListenerError> {
        Ok(Session::accept_classified(self.incoming, self.session_identity).await?)
    }
}

pub struct AnchorListener {
    endpoint: quinn::Endpoint,
    session_identity: SessionIdentity,
}

impl AnchorListener {
    pub fn bind(config: ListenerConfig) -> Result<Self, ListenerError> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let server_config = quinn_transport::server_config(config.identity.server_config()?)
            .map_err(|_| ListenerError::TransportConfiguration)?;
        let socket =
            quinn_transport::bind_udp_socket(config.bind_address).map_err(ListenerError::Bind)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| ListenerError::Bind(std::io::Error::other("no async runtime")))?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(ListenerError::Bind)?;
        Ok(Self {
            endpoint,
            session_identity: config.session_identity,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        self.endpoint.local_addr().map_err(ListenerError::Bind)
    }

    pub async fn accept(&self) -> Result<Option<IncomingConnection>, ListenerError> {
        let Some(incoming) = self.endpoint.accept().await else {
            return Ok(None);
        };
        Ok(Some(IncomingConnection {
            incoming,
            session_identity: self.session_identity.clone(),
        }))
    }
}

#[derive(Debug)]
struct AcceptAnyClientCertificate {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl AcceptAnyClientCertificate {
    fn new() -> Self {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        Self {
            supported_algs: provider.signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for AcceptAnyClientCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
