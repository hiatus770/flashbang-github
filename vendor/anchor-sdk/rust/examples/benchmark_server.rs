//! Paired raw-UDP and Anchor/QUIC echo server for transport measurements.
//!
//! The server intentionally echoes the application bytes unchanged. This lets
//! the Android test use the same payload, sequence number, and packet count for
//! both transports while measuring RTT, loss, and goodput on the same route.

use std::{fs::File, io::BufReader, sync::Arc};

use anchor_sdk::quinn_transport;
use quinn::Endpoint;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::net::UdpSocket;

const UDP_PORT: u16 = 4450;
const QUIC_PORT: u16 = 4451;

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

fn server_endpoint(fixture_root: &str) -> Endpoint {
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
    Endpoint::server(
        quinn_transport::server_config(tls).unwrap(),
        format!("0.0.0.0:{QUIC_PORT}").parse().unwrap(),
    )
    .unwrap()
}

#[tokio::main]
async fn main() {
    let fixture_root = "../kotlin/src/androidTest/assets/mtls";
    let udp = UdpSocket::bind(format!("0.0.0.0:{UDP_PORT}"))
        .await
        .unwrap();
    let endpoint = server_endpoint(fixture_root);
    println!("READY udp={UDP_PORT} quic={QUIC_PORT}");

    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&buffer[..length], peer).await.unwrap();
        }
    });

    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else {
                return;
            };
            println!("QUIC_CONNECTED {}", connection.remote_address());
            while let Ok(datagram) = connection.read_datagram().await {
                if connection.send_datagram_wait(datagram).await.is_err() {
                    break;
                }
            }
        });
    }
}
