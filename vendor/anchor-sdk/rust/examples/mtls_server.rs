use std::{fs::File, io::BufReader, sync::Arc, time::Duration};

use anchor_sdk::quinn_transport;
use bytes::Bytes;
use quinn::Endpoint;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};

fn certificates(path: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn private_key(path: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path).unwrap()))
        .unwrap()
        .unwrap()
}

#[tokio::main]
async fn main() {
    let fixture_root = "../kotlin/src/androidTest/assets/mtls";
    let server_certificates = certificates(&format!("{fixture_root}/server-cert.pem"));
    let server_key = private_key(&format!("{fixture_root}/server-key.pem"));
    let mut client_roots = RootCertStore::empty();
    for certificate in certificates(&format!("{fixture_root}/client-cert.pem")) {
        client_roots.add(certificate).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .unwrap();
    let tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certificates, server_key)
        .unwrap();
    let endpoint = Endpoint::server(
        quinn_transport::server_config(tls).unwrap(),
        "0.0.0.0:4443".parse().unwrap(),
    )
    .unwrap();

    println!("READY 4443");
    let connection = endpoint.accept().await.unwrap().await.unwrap();
    println!("CONNECTED {}", connection.remote_address());
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    let received = recv.read_to_end(1024 * 1024).await.unwrap();
    println!("STREAM {}", String::from_utf8_lossy(&received));
    send.write_all(b"quinn-stream-response").await.unwrap();
    send.finish().unwrap();
    let (mut peer_send, _peer_recv) = connection.open_bi().await.unwrap();
    peer_send.write_all(b"quinn-peer-stream").await.unwrap();
    peer_send.finish().unwrap();
    let datagram = connection.read_datagram().await.unwrap();
    println!("DATAGRAM {}", String::from_utf8_lossy(&datagram));
    connection
        .send_datagram(Bytes::from_static(b"quinn-datagram-response"))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
}
