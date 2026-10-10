use std::sync::Arc;

use anchor_sdk::{ALPN, quinn_transport};
use bytes::Bytes;
use quinn::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

fn test_configs() -> (
    quinn::ServerConfig,
    quinn::ClientConfig,
    CertificateDer<'static>,
) {
    let certificate = generate_simple_self_signed(vec!["anchor.test".into()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    ));

    let server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (
        quinn_transport::server_config(server_tls).unwrap(),
        quinn_transport::client_config(client_tls).unwrap(),
        certificate_der,
    )
}

fn mutually_authenticated_configs() -> (quinn::ServerConfig, quinn::ClientConfig) {
    let server_certificate = generate_simple_self_signed(vec!["anchor.test".into()]).unwrap();
    let server_certificate_der = CertificateDer::from(server_certificate.cert.der().to_vec());
    let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        server_certificate.signing_key.serialize_der(),
    ));

    let client_certificate = generate_simple_self_signed(vec!["anchor-client".into()]).unwrap();
    let client_certificate_der = CertificateDer::from(client_certificate.cert.der().to_vec());
    let client_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        client_certificate.signing_key.serialize_der(),
    ));

    let mut client_roots = RootCertStore::empty();
    client_roots.add(server_certificate_der.clone()).unwrap();
    let client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(client_roots)
        .with_client_auth_cert(vec![client_certificate_der.clone()], client_key)
        .unwrap();

    let mut server_client_roots = RootCertStore::empty();
    server_client_roots.add(client_certificate_der).unwrap();
    let client_verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(server_client_roots))
            .build()
            .unwrap();
    let server_tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_certificate_der], server_key)
        .unwrap();

    (
        quinn_transport::server_config(server_tls).unwrap(),
        quinn_transport::client_config(client_tls).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_alpn_control_stream_and_datagram_work_over_quinn() {
    let (server_config, client_config, _) = test_configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        assert_eq!(
            connection
                .handshake_data()
                .unwrap()
                .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                .unwrap()
                .protocol,
            Some(ALPN.to_vec())
        );

        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let received = recv.read_to_end(1024).await.unwrap();
        assert_eq!(received, b"anchor-control");
        send.write_all(b"control-ok").await.unwrap();
        send.finish().unwrap();

        assert_eq!(
            connection.read_datagram().await.unwrap(),
            Bytes::from_static(b"screen-frame")
        );
    });

    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let connection = client
        .connect(address, "anchor.test")
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        connection
            .handshake_data()
            .unwrap()
            .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
            .unwrap()
            .protocol,
        Some(ALPN.to_vec())
    );

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"anchor-control").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1024).await.unwrap(), b"control-ok");
    connection
        .send_datagram(Bytes::from_static(b"screen-frame"))
        .unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_alpn_cannot_establish_an_anchor_connection() {
    let (server_config, _, certificate_der) = test_configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move { server.accept().await.unwrap().await });

    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"not-anchor".to_vec()];
    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));

    assert!(
        client
            .connect(address, "anchor.test")
            .unwrap()
            .await
            .is_err()
    );
    assert!(server_task.await.unwrap().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_server_name_cannot_establish_an_anchor_connection() {
    let (server_config, client_config, _) = test_configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move { server.accept().await.unwrap().await });

    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    assert!(
        client
            .connect(address, "different-anchor.test")
            .unwrap()
            .await
            .is_err(),
        "the certificate name must be checked before Anchor receives control records",
    );
    assert!(server_task.await.unwrap().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutually_authenticated_peers_negotiate_anchor_alpn() {
    let (server_config, client_config) = mutually_authenticated_configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        assert_eq!(
            connection
                .handshake_data()
                .unwrap()
                .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                .unwrap()
                .protocol,
            Some(ALPN.to_vec())
        );
    });

    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    client
        .connect(address, "anchor.test")
        .unwrap()
        .await
        .unwrap();
    server_task.await.unwrap();
}
