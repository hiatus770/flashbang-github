//! Rust Session API peer used by the Android end-to-end proof of concept, and
//! as a local (non-CI) Rust<->Kotlin interop fixture. See
//! `anchor-sdk/rust/examples/README.md` for how to run it against the Kotlin
//! SDK's instrumented tests.

use std::{collections::HashMap, fs::File, io::BufReader, sync::Arc};

use anchor_sdk::{Capability, Session, SessionEvent, SessionIdentity, clipboard, quinn_transport};
use quinn::Endpoint;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::time::{Duration, sleep};

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
    let root = std::env::var("ANCHOR_TEST_CERT_DIR")
        .unwrap_or_else(|_| "../kotlin/src/androidTest/assets/mtls".into());
    let bind_addr =
        std::env::var("ANCHOR_TEST_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:4452".into());
    let mut client_roots = RootCertStore::empty();
    for cert in certificates(&format!("{root}/client-cert.pem")) {
        client_roots.add(cert).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .unwrap();
    let tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            certificates(&format!("{root}/server-cert.pem")),
            private_key(&format!("{root}/server-key.pem")),
        )
        .unwrap();
    let endpoint = Endpoint::server(
        quinn_transport::server_config(tls).unwrap(),
        bind_addr.parse().unwrap(),
    )
    .unwrap();

    // Test-only mode: simulate a peer on a newer, unsupported protocol minor
    // instead of running a real session, so a Kotlin-side interop test can
    // assert the connect attempt is rejected. Never used by a real
    // AnchorListener/PairingSession, which always send the SDK's own minor.
    if let Ok(forced_minor) = std::env::var("ANCHOR_TEST_FORCE_MINOR") {
        let minor: u8 = forced_minor
            .parse()
            .expect("ANCHOR_TEST_FORCE_MINOR must be a u8");
        println!("READY {}", bind_addr.rsplit(':').next().unwrap());
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send.write_all(b"ANCR").await.unwrap();
        send.write_all(&[1, minor]).await.unwrap();
        send.finish().unwrap();
        println!("FORCED_MINOR_SENT {minor}");
        sleep(Duration::from_secs(2)).await;
        return;
    }

    let identity = SessionIdentity {
        node_id: [3; 32],
        display_name: "Rust session fixture".into(),
        device_kind: 1,
        // Advertise both a reliable record capability and a datagram-capable
        // media capability so the Android fixture can exercise each transport
        // path in one authenticated session.
        endpoints: vec![anchor_sdk::v1::EndpointAdvertisement {
            endpoint_id: anchor_sdk::clipboard::ENDPOINT_ID.into(),
            capabilities: vec![
                anchor_sdk::clipboard::advertisement(),
                anchor_sdk::screen::advertisement(),
            ],
        }],
    };
    println!("READY {}", bind_addr.rsplit(':').next().unwrap());
    let session = Session::accept(endpoint.accept().await.unwrap(), identity)
        .await
        .unwrap();
    println!("SESSION_READY {}", session.peer().display_name);
    let mut capabilities: HashMap<u64, Capability> = HashMap::new();
    loop {
        match session.next_event().await.unwrap() {
            SessionEvent::CapabilityOpenRequested {
                request_id,
                capability_session_id,
                endpoint_id,
                capability_name,
                capability_major,
            } => {
                session.send_ping(42).await.unwrap();
                let capability = session
                    .accept_capability(
                        request_id,
                        capability_session_id,
                        &endpoint_id,
                        &capability_name,
                        capability_major,
                    )
                    .await
                    .unwrap();
                capabilities.insert(capability_session_id, capability);
            }
            SessionEvent::CapabilityRecord {
                capability_session_id,
                type_url,
                payload,
            } => {
                if type_url == clipboard::PUBLISH_TYPE_URL {
                    // A real typed round trip: decode with the same SDK
                    // helper an application would use, then echo a typed
                    // acknowledgement back so the peer can assert on it
                    // instead of only reading this process's stdout.
                    let publish = clipboard::decode_publish(&payload).unwrap();
                    println!("RECORD ClipboardPublish revision={}", publish.revision);
                    if let Some(capability) = capabilities.get(&capability_session_id) {
                        capability
                            .send_record(
                                clipboard::CLEAR_TYPE_URL,
                                clipboard::encode_clear([3; 32], publish.revision + 1),
                            )
                            .await
                            .unwrap();
                    }
                } else {
                    println!("RECORD {}", String::from_utf8_lossy(&payload))
                }
            }
            SessionEvent::StreamOpenRequested {
                request_id,
                quic_stream_id,
                ..
            } => {
                let stream = session
                    .accept_stream(request_id, quic_stream_id)
                    .await
                    .unwrap();
                let (mut send, mut recv) = stream.into_parts();
                let mut data = Vec::new();
                while let Some(chunk) = recv.read_chunk(16 * 1024, true).await.unwrap() {
                    data.extend_from_slice(&chunk);
                    assert!(
                        data.len() <= 1024 * 1024,
                        "stream exceeds 1 MiB example limit"
                    );
                }
                println!("STREAM {}", String::from_utf8_lossy(&data));
                send.write_all(b"rust-session-stream-response")
                    .await
                    .unwrap();
                send.finish().unwrap();
                // Keep the endpoint alive long enough for the FIN and final
                // response to reach a mobile peer before the fixture exits.
                sleep(Duration::from_millis(100)).await;
                break;
            }
            SessionEvent::DatagramFlowOpenRequested {
                request_id,
                flow_id,
                ..
            } => {
                let flow = session
                    .accept_datagram_flow(request_id, flow_id)
                    .await
                    .unwrap();
                let payload = flow.recv().await.unwrap();
                println!("DATAGRAM {}", String::from_utf8_lossy(&payload));
            }
            _ => {}
        }
    }
}
