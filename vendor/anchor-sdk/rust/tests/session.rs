use anchor_sdk::{
    AcceptedSession, PairingSession, SessionEvent, SessionIdentity, encode_first_control_record,
    quinn_transport,
    session::{Session, SessionError},
    v1,
};
use proptest::prelude::*;
use prost::Message;
use quinn::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    time::{Duration, sleep, timeout},
};

#[derive(Clone, Copy, Debug)]
enum CapabilityOpenInterleaving {
    Ping,
    WrongRequest,
    WrongCapability,
    Correct,
}

fn encode_followup_control_record(envelope: &v1::ControlEnvelope) -> Vec<u8> {
    let mut value = envelope.encode_to_vec().len() as u64;
    let mut frame = Vec::new();
    while value >= 0x80 {
        frame.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    frame.push(value as u8);
    frame.extend_from_slice(&envelope.encode_to_vec());
    frame
}

async fn read_raw_varint(recv: &mut quinn::RecvStream) -> u64 {
    let mut value = 0_u64;
    for index in 0..10 {
        let byte = recv.read_u8().await.unwrap();
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return value;
        }
    }
    panic!("test peer received an overlong control length");
}

async fn read_raw_control_record(
    recv: &mut quinn::RecvStream,
    first: &mut bool,
) -> v1::ControlEnvelope {
    if *first {
        let mut prefix = [0_u8; 6];
        recv.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[..4], b"ANCR");
        assert_eq!(&prefix[4..], &[1, 0]);
        *first = false;
    }
    let length = usize::try_from(read_raw_varint(recv).await).unwrap();
    let mut payload = vec![0_u8; length];
    recv.read_exact(&mut payload).await.unwrap();
    v1::ControlEnvelope::decode(payload.as_slice()).unwrap()
}

fn raw_session_hello(endpoints: Vec<v1::EndpointAdvertisement>) -> v1::ControlEnvelope {
    v1::ControlEnvelope {
        request_id: 0,
        response_to: 0,
        body: Some(v1::control_envelope::Body::SessionHello(v1::SessionHello {
            protocol_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
            node_id: Some(v1::NodeId { value: vec![9; 32] }),
            display: Some(v1::PeerDisplayInfo {
                display_name: "raw test peer".into(),
                device_kind: 2,
            }),
            endpoints,
        })),
    }
}

fn session_ready() -> v1::ControlEnvelope {
    session_ready_with_version(Some(v1::ProtocolVersion { major: 1, minor: 0 }))
}

fn session_ready_with_version(
    protocol_version: Option<v1::ProtocolVersion>,
) -> v1::ControlEnvelope {
    v1::ControlEnvelope {
        request_id: 0,
        response_to: 0,
        body: Some(v1::control_envelope::Body::SessionReady(v1::SessionReady {
            protocol_version,
        })),
    }
}

fn configs() -> (quinn::ServerConfig, quinn::ClientConfig) {
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
    roots.add(certificate_der).unwrap();
    let client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        quinn_transport::server_config(server_tls).unwrap(),
        quinn_transport::client_config(client_tls).unwrap(),
    )
}

fn identity(endpoints: Vec<anchor_sdk::v1::EndpointAdvertisement>) -> SessionIdentity {
    SessionIdentity {
        node_id: [7; 32],
        display_name: "test-peer".into(),
        device_kind: 1,
        endpoints,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_handshake_and_capability_record_round_trip() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let advertisement = anchor_sdk::v1::EndpointAdvertisement {
        endpoint_id: "io.anchor.desktop".into(),
        capabilities: vec![anchor_sdk::v1::CapabilityAdvertisement {
            name: "org.anchor.clipboard".into(),
            major: 1,
            record_type_urls: vec![anchor_sdk::clipboard::PUBLISH_TYPE_URL.into()],
            supports_datagrams: false,
        }],
    };
    let server_task = tokio::spawn(async move {
        let connecting = server.accept().await.unwrap();
        let session = Session::accept(connecting, identity(vec![advertisement.clone()]))
            .await
            .unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            endpoint_id,
            capability_name,
            capability_major,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected capability open request");
        };
        session.send_ping(42).await.unwrap();
        session
            .accept_capability(
                request_id,
                capability_session_id,
                &endpoint_id,
                &capability_name,
                capability_major,
            )
            .await
            .unwrap();
        let SessionEvent::CapabilityRecord {
            capability_session_id: received_id,
            type_url,
            payload,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected capability record");
        };
        assert_eq!(received_id, capability_session_id);
        assert_eq!(type_url, anchor_sdk::clipboard::PUBLISH_TYPE_URL);
        assert_eq!(payload, b"clipboard".to_vec());
        let SessionEvent::StreamOpenRequested {
            request_id,
            quic_stream_id,
            capability_session_id: stream_capability,
            payload_type_url,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected stream open request");
        };
        assert_eq!(stream_capability, capability_session_id);
        assert_eq!(payload_type_url, anchor_sdk::clipboard::PUBLISH_TYPE_URL);
        let stream = session
            .accept_stream(request_id, quic_stream_id)
            .await
            .unwrap();
        let (_send, mut recv) = stream.into_parts();
        assert_eq!(
            recv.read_chunk(1024, true).await.unwrap().unwrap().as_ref(),
            b"stream-data"
        );
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();
    let capability = client
        .open_capability("io.anchor.desktop", "org.anchor.clipboard", 1)
        .await
        .unwrap();
    assert_eq!(
        client.next_event().await.unwrap(),
        SessionEvent::Ping { nonce: 42 }
    );
    capability
        .send_record(
            anchor_sdk::clipboard::PUBLISH_TYPE_URL,
            b"clipboard".to_vec(),
        )
        .await
        .unwrap();
    let stream = capability
        .open_stream(anchor_sdk::clipboard::PUBLISH_TYPE_URL)
        .await
        .unwrap();
    let (mut stream_send, _stream_recv) = stream.into_parts();
    stream_send.write_all(b"stream-data").await.unwrap();
    stream_send.finish().unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_ready_requires_a_compatible_explicit_protocol_version() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        Session::accept(incoming, identity(vec![])).await
    });

    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let connection = client
        .connect(address, "anchor.test")
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    let mut handshake = encode_first_control_record(&raw_session_hello(vec![])).unwrap();
    handshake.extend_from_slice(&encode_followup_control_record(
        &session_ready_with_version(Some(v1::ProtocolVersion { major: 1, minor: 1 })),
    ));
    send.write_all(&handshake).await.unwrap();
    send.flush().await.unwrap();

    let accepted = timeout(Duration::from_millis(250), server_task)
        .await
        .expect("the responder must decide handshake compatibility promptly")
        .unwrap();
    assert!(
        accepted.is_err(),
        "a future-minor SessionReady must not establish a session",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_open_rejects_an_id_that_cannot_be_peer_bidirectional() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(incoming, identity(vec![])).await.unwrap();
        let SessionEvent::StreamOpenRequested {
            request_id,
            quic_stream_id,
            ..
        } = session.next_event().await.unwrap()
        else {
            panic!("expected a stream open request");
        };
        session.accept_stream(request_id, quic_stream_id).await
    });

    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let connection = client
        .connect(address, "anchor.test")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut handshake = encode_first_control_record(&raw_session_hello(vec![])).unwrap();
    handshake.extend_from_slice(&encode_followup_control_record(&session_ready()));
    send.write_all(&handshake).await.unwrap();
    send.flush().await.unwrap();

    let mut first_response = true;
    assert!(matches!(
        read_raw_control_record(&mut recv, &mut first_response)
            .await
            .body,
        Some(v1::control_envelope::Body::SessionHello(_)),
    ));
    assert!(matches!(
        read_raw_control_record(&mut recv, &mut first_response)
            .await
            .body,
        Some(v1::control_envelope::Body::SessionReady(_)),
    ));

    let forged_stream_id = 999;
    let open = v1::ControlEnvelope {
        request_id: 1,
        response_to: 0,
        body: Some(v1::control_envelope::Body::StreamOpen(v1::StreamOpen {
            quic_stream_id: forged_stream_id,
            capability_session_id: 1,
            payload_type_url: anchor_sdk::clipboard::PUBLISH_TYPE_URL.into(),
        })),
    };
    send.write_all(&encode_followup_control_record(&open))
        .await
        .unwrap();
    send.flush().await.unwrap();

    assert!(
        !matches!(
            timeout(Duration::from_millis(100), recv.read_chunk(1, true)).await,
            Ok(Ok(Some(_)))
        ),
        "an invalid StreamOpen ID must not receive StreamOpened",
    );

    connection.close(0u32.into(), b"test complete");
    let result = timeout(Duration::from_millis(250), server_task)
        .await
        .expect("the pending stream accept must unblock when the connection closes")
        .unwrap();
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_capability_open_fails_promptly_when_quic_closes() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::clipboard::endpoint_advertisement()]),
        )
        .await
        .unwrap();
        assert!(matches!(
            session.next_event().await.unwrap(),
            SessionEvent::CapabilityOpenRequested { .. },
        ));
        session.close(0, b"test connection loss");
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();

    let result = timeout(
        Duration::from_millis(250),
        client.open_capability(
            anchor_sdk::clipboard::ENDPOINT_ID,
            anchor_sdk::clipboard::CAPABILITY_NAME,
            anchor_sdk::clipboard::CAPABILITY_MAJOR,
        ),
    )
    .await
    .expect("connection loss must wake a capability-open waiter");
    assert!(
        result.is_err(),
        "a closed connection cannot open a capability"
    );
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_control_stream_fin_has_a_stable_terminal_session_error() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(incoming, identity(vec![])).await.unwrap();
        session.next_event().await
    });

    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let connection = client
        .connect(address, "anchor.test")
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    let mut handshake = encode_first_control_record(&raw_session_hello(vec![])).unwrap();
    handshake.extend_from_slice(&encode_followup_control_record(&session_ready()));
    send.write_all(&handshake).await.unwrap();
    send.finish().unwrap();

    let result = timeout(Duration::from_millis(250), server_task)
        .await
        .expect("control-stream FIN must wake the session reader")
        .unwrap();
    assert!(matches!(result, Err(SessionError::ControlStreamEnded)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remotely_closed_capability_handle_cannot_send_another_record() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::clipboard::endpoint_advertisement()]),
        )
        .await
        .unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            endpoint_id,
            capability_name,
            capability_major,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected capability open request");
        };
        session
            .accept_capability(
                request_id,
                capability_session_id,
                &endpoint_id,
                &capability_name,
                capability_major,
            )
            .await
            .unwrap();
        session
            .send_capability_closed(capability_session_id, 0)
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), session.next_event())
                .await
                .is_err(),
            "a locally invalidated handle must not put another control record on the wire",
        );
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();
    let capability = client
        .open_capability(
            anchor_sdk::clipboard::ENDPOINT_ID,
            anchor_sdk::clipboard::CAPABILITY_NAME,
            anchor_sdk::clipboard::CAPABILITY_MAJOR,
        )
        .await
        .unwrap();
    let stale_handle = capability.clone();
    assert!(matches!(
        client.next_event().await.unwrap(),
        SessionEvent::CapabilityClosed { capability_session_id, .. }
            if capability_session_id == capability.session_id(),
    ));
    assert!(
        stale_handle
            .send_record(
                anchor_sdk::clipboard::PUBLISH_TYPE_URL,
                b"after close".to_vec()
            )
            .await
            .is_err(),
        "a remote close must invalidate every local capability handle",
    );

    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_stream_opens_cannot_consume_each_others_replies() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let (first_open_tx, first_open_rx) = oneshot::channel();
    let (completed_tx, completed_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::clipboard::endpoint_advertisement()]),
        )
        .await
        .unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            endpoint_id,
            capability_name,
            capability_major,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected capability open request");
        };
        session
            .accept_capability(
                request_id,
                capability_session_id,
                &endpoint_id,
                &capability_name,
                capability_major,
            )
            .await
            .unwrap();

        let SessionEvent::StreamOpenRequested {
            request_id: first_request_id,
            quic_stream_id: first_stream_id,
            ..
        } = session.next_event().await.unwrap()
        else {
            panic!("expected first stream open request");
        };
        first_open_tx.send(()).unwrap();
        let SessionEvent::StreamOpenRequested {
            request_id: second_request_id,
            quic_stream_id: second_stream_id,
            ..
        } = session.next_event().await.unwrap()
        else {
            panic!("expected second stream open request");
        };

        session
            .send_stream_opened(second_request_id, second_stream_id)
            .await
            .unwrap();
        session
            .send_stream_opened(first_request_id, first_stream_id)
            .await
            .unwrap();
        let _ = completed_rx.await;
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();
    let capability = client
        .open_capability(
            anchor_sdk::clipboard::ENDPOINT_ID,
            anchor_sdk::clipboard::CAPABILITY_NAME,
            anchor_sdk::clipboard::CAPABILITY_MAJOR,
        )
        .await
        .unwrap();

    let first_capability = capability.clone();
    let first_open = tokio::spawn(async move {
        first_capability
            .open_stream(anchor_sdk::clipboard::PUBLISH_TYPE_URL)
            .await
    });
    first_open_rx.await.unwrap();
    let second_capability = capability.clone();
    let second_open = tokio::spawn(async move {
        second_capability
            .open_stream(anchor_sdk::clipboard::PUBLISH_TYPE_URL)
            .await
    });

    let (_first, _second) = timeout(Duration::from_millis(250), async {
        (
            first_open.await.unwrap().unwrap(),
            second_open.await.unwrap().unwrap(),
        )
    })
    .await
    .expect("concurrent stream opens must not wait for replies already received");

    completed_tx.send(()).unwrap();
    client.close(0, b"test complete");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_datagram_flow_opens_cannot_consume_each_others_replies() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let (first_open_tx, first_open_rx) = oneshot::channel();
    let (completed_tx, completed_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::camera::endpoint_advertisement()]),
        )
        .await
        .unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            endpoint_id,
            capability_name,
            capability_major,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected capability open request");
        };
        session
            .accept_capability(
                request_id,
                capability_session_id,
                &endpoint_id,
                &capability_name,
                capability_major,
            )
            .await
            .unwrap();

        let SessionEvent::DatagramFlowOpenRequested {
            request_id: first_request_id,
            flow_id: first_flow_id,
            ..
        } = session.next_event().await.unwrap()
        else {
            panic!("expected first datagram flow open request");
        };
        first_open_tx.send(()).unwrap();
        let SessionEvent::DatagramFlowOpenRequested {
            request_id: second_request_id,
            flow_id: second_flow_id,
            ..
        } = session.next_event().await.unwrap()
        else {
            panic!("expected second datagram flow open request");
        };

        session
            .send_datagram_flow_opened(second_request_id, second_flow_id)
            .await
            .unwrap();
        session
            .send_datagram_flow_opened(first_request_id, first_flow_id)
            .await
            .unwrap();
        let _ = completed_rx.await;
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();
    let capability = client
        .open_capability(
            anchor_sdk::camera::ENDPOINT_ID,
            anchor_sdk::camera::CAPABILITY_NAME,
            anchor_sdk::camera::CAPABILITY_MAJOR,
        )
        .await
        .unwrap();

    let first_capability = capability.clone();
    let first_open = tokio::spawn(async move {
        first_capability
            .open_datagram_flow(anchor_sdk::camera::FRAME_TYPE_URL)
            .await
    });
    first_open_rx.await.unwrap();
    let second_capability = capability.clone();
    let second_open = tokio::spawn(async move {
        second_capability
            .open_datagram_flow(anchor_sdk::camera::FRAME_TYPE_URL)
            .await
    });

    let (first, second) = timeout(Duration::from_millis(250), async {
        (
            first_open.await.unwrap().unwrap(),
            second_open.await.unwrap().unwrap(),
        )
    })
    .await
    .expect("concurrent datagram opens must not wait for replies already received");
    assert_ne!(first.flow_id(), second.flow_id());

    completed_tx.send(()).unwrap();
    client.close(0, b"test complete");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unbound_capability_cannot_receive_a_datagram_flow_acknowledgement() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::camera::endpoint_advertisement()]),
        )
        .await
        .unwrap();
        assert!(session.next_event().await.is_err());
    });

    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let connection = client
        .connect(address, "anchor.test")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut handshake = encode_first_control_record(&raw_session_hello(vec![])).unwrap();
    handshake.extend_from_slice(&encode_followup_control_record(&session_ready()));
    send.write_all(&handshake).await.unwrap();
    send.flush().await.unwrap();

    let mut first_response = true;
    assert!(matches!(
        read_raw_control_record(&mut recv, &mut first_response)
            .await
            .body,
        Some(v1::control_envelope::Body::SessionHello(_)),
    ));
    assert!(matches!(
        read_raw_control_record(&mut recv, &mut first_response)
            .await
            .body,
        Some(v1::control_envelope::Body::SessionReady(_)),
    ));

    let open = v1::ControlEnvelope {
        request_id: 1,
        response_to: 0,
        body: Some(v1::control_envelope::Body::DatagramFlowOpen(
            v1::DatagramFlowOpen {
                capability_session_id: 777,
                flow_id: 1,
                payload_type_url: anchor_sdk::camera::FRAME_TYPE_URL.into(),
            },
        )),
    };
    send.write_all(&encode_followup_control_record(&open))
        .await
        .unwrap();
    send.flush().await.unwrap();

    assert!(
        !matches!(
            timeout(Duration::from_millis(100), recv.read_chunk(1, true)).await,
            Ok(Ok(Some(_)))
        ),
        "an unbound capability session must not receive DatagramFlowOpened",
    );

    connection.close(0u32.into(), b"test complete");
    timeout(Duration::from_millis(250), server_task)
        .await
        .expect("the pending datagram admission must unblock when the connection closes")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capability_open_matches_only_its_exact_reply_and_preserves_other_events() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();

    let advertisement = anchor_sdk::v1::EndpointAdvertisement {
        endpoint_id: "io.anchor.desktop".into(),
        capabilities: vec![anchor_sdk::v1::CapabilityAdvertisement {
            name: "org.anchor.clipboard".into(),
            major: 1,
            record_type_urls: vec![anchor_sdk::clipboard::PUBLISH_TYPE_URL.into()],
            supports_datagrams: false,
        }],
    };

    let (opened_tx, opened_rx) = oneshot::channel();
    let (completed_tx, completed_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(incoming, identity(vec![advertisement]))
            .await
            .unwrap();

        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            ..
        } = session.next_event().await.unwrap()
        else {
            panic!("expected capability open request");
        };

        opened_tx.send((request_id, capability_session_id)).unwrap();

        session.send_ping(99).await.unwrap();
        session
            .send_capability_opened(request_id + 1, capability_session_id)
            .await
            .unwrap();
        session
            .send_capability_opened(request_id, capability_session_id + 1)
            .await
            .unwrap();
        session
            .send_capability_opened(request_id, capability_session_id)
            .await
            .unwrap();

        let _ = completed_rx.await;
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();

    let capability = client
        .open_capability("io.anchor.desktop", "org.anchor.clipboard", 1)
        .await
        .unwrap();

    let (request_id, capability_session_id) = opened_rx.await.unwrap();
    assert_eq!(capability.session_id(), capability_session_id);
    assert_eq!(
        client.next_event().await.unwrap(),
        SessionEvent::Ping { nonce: 99 },
    );
    assert_eq!(
        client.next_event().await.unwrap(),
        SessionEvent::CapabilityOpened {
            response_to: request_id + 1,
            capability_session_id,
        },
    );
    assert_eq!(
        client.next_event().await.unwrap(),
        SessionEvent::CapabilityOpened {
            response_to: request_id,
            capability_session_id: capability_session_id + 1,
        },
    );

    completed_tx.send(()).unwrap();
    client.close(0, b"test complete");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_capability_opens_cannot_consume_each_others_replies() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let advertisement = anchor_sdk::v1::EndpointAdvertisement {
        endpoint_id: "io.anchor.desktop".into(),
        capabilities: vec![
            anchor_sdk::clipboard::advertisement(),
            anchor_sdk::media::advertisement(),
        ],
    };
    let (first_open_tx, first_open_rx) = oneshot::channel();
    let (completed_tx, completed_rx) = oneshot::channel();

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(incoming, identity(vec![advertisement]))
            .await
            .unwrap();
        let first = session.next_event().await.unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id: first_request_id,
            capability_session_id: first_capability_id,
            ..
        } = first
        else {
            panic!("expected the first capability open request");
        };
        first_open_tx.send(()).unwrap();

        let second = session.next_event().await.unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id: second_request_id,
            capability_session_id: second_capability_id,
            ..
        } = second
        else {
            panic!("expected the second capability open request");
        };

        // The first opener is already awaiting a control record. Give the
        // second opener time to queue behind that reader, then reply to the
        // second request first. A correct request router delivers each reply
        // to its owner rather than letting the readers exchange them.
        sleep(Duration::from_millis(20)).await;
        session
            .send_capability_opened(second_request_id, second_capability_id)
            .await
            .unwrap();
        session
            .send_capability_opened(first_request_id, first_capability_id)
            .await
            .unwrap();
        let _ = completed_rx.await;
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();

    let first_client = client.clone();
    let first_open = tokio::spawn(async move {
        first_client
            .open_capability("io.anchor.desktop", "org.anchor.clipboard", 1)
            .await
    });
    first_open_rx.await.unwrap();
    let second_client = client.clone();
    let second_open = tokio::spawn(async move {
        second_client
            .open_capability("io.anchor.desktop", "org.anchor.media", 1)
            .await
    });

    let (clipboard, media) = timeout(Duration::from_millis(250), async {
        (
            first_open.await.unwrap().unwrap(),
            second_open.await.unwrap().unwrap(),
        )
    })
    .await
    .expect("concurrent capability opens must not wait for replies already received");
    assert_ne!(clipboard.session_id(), media.session_id());

    completed_tx.send(()).unwrap();
    client.close(0, b"test complete");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unadvertised_record_type_is_never_exposed_as_a_capability_event() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::clipboard::endpoint_advertisement()]),
        )
        .await
        .unwrap();

        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            endpoint_id,
            capability_name,
            capability_major,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected a clipboard capability open request");
        };
        session
            .accept_capability(
                request_id,
                capability_session_id,
                &endpoint_id,
                &capability_name,
                capability_major,
            )
            .await
            .unwrap();

        assert!(session.next_event().await.is_err());
    });

    let mut client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let connection = client
        .connect(address, "anchor.test")
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    let hello = raw_session_hello(vec![]);
    let mut handshake = encode_first_control_record(&hello).unwrap();
    handshake.extend_from_slice(&encode_followup_control_record(&session_ready()));
    send.write_all(&handshake).await.unwrap();
    send.flush().await.unwrap();

    let open = v1::ControlEnvelope {
        request_id: 1,
        response_to: 0,
        body: Some(v1::control_envelope::Body::CapabilityOpen(
            v1::CapabilityOpen {
                capability_session_id: 1,
                endpoint_id: anchor_sdk::clipboard::ENDPOINT_ID.into(),
                capability_name: anchor_sdk::clipboard::CAPABILITY_NAME.into(),
                capability_major: anchor_sdk::clipboard::CAPABILITY_MAJOR,
            },
        )),
    };
    send.write_all(&encode_followup_control_record(&open))
        .await
        .unwrap();
    send.flush().await.unwrap();

    let malicious_record = v1::ControlEnvelope {
        request_id: 0,
        response_to: 0,
        body: Some(v1::control_envelope::Body::CapabilityRecord(
            v1::CapabilityRecord {
                capability_session_id: 1,
                type_url: anchor_sdk::media::STATE_TYPE_URL.into(),
                payload: vec![0],
            },
        )),
    };
    send.write_all(&encode_followup_control_record(&malicious_record))
        .await
        .unwrap();
    send.flush().await.unwrap();

    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_capability_session_cannot_send_or_dispatch_later_records() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let advertisement = anchor_sdk::clipboard::endpoint_advertisement();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(incoming, identity(vec![advertisement]))
            .await
            .unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            endpoint_id,
            capability_name,
            capability_major,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected a clipboard capability open request");
        };
        session
            .accept_capability(
                request_id,
                capability_session_id,
                &endpoint_id,
                &capability_name,
                capability_major,
            )
            .await
            .unwrap();
        assert!(matches!(
            session.next_event().await.unwrap(),
            SessionEvent::CapabilityClosed {
                capability_session_id: closed,
                ..
            } if closed == capability_session_id
        ));

        assert!(session.next_event().await.is_err());
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();
    let capability = client
        .open_capability(
            anchor_sdk::clipboard::ENDPOINT_ID,
            anchor_sdk::clipboard::CAPABILITY_NAME,
            anchor_sdk::clipboard::CAPABILITY_MAJOR,
        )
        .await
        .unwrap();
    client
        .send_capability_closed(capability.session_id(), 0)
        .await
        .unwrap();
    capability
        .send_record(
            anchor_sdk::clipboard::PUBLISH_TYPE_URL,
            b"after close".to_vec(),
        )
        .await
        .unwrap();

    server_task.await.unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn capability_open_routes_only_its_exact_reply_under_interleaving(
        order_keys in (any::<u64>(), any::<u64>(), any::<u64>(), any::<u64>()),
        ping_nonce in any::<u64>(),
        wrong_request_mask in 1u64..,
        wrong_capability_mask in 1u64..,
    ) {
        let mut interleaving = vec![
            (order_keys.0, 0_u8, CapabilityOpenInterleaving::Ping),
            (order_keys.1, 1_u8, CapabilityOpenInterleaving::WrongRequest),
            (order_keys.2, 2_u8, CapabilityOpenInterleaving::WrongCapability),
            (order_keys.3, 3_u8, CapabilityOpenInterleaving::Correct),
        ];
        // The second key makes ties deterministic while leaving every event
        // order reachable through the generated first keys.
        interleaving.sort_by_key(|(key, tie_breaker, _)| (*key, *tie_breaker));
        let interleaving = interleaving
            .into_iter()
            .map(|(_, _, event)| event)
            .collect::<Vec<_>>();
        let server_interleaving = interleaving.clone();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (server_config, client_config) = configs();
            let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = server.local_addr().unwrap();
            let advertisement = anchor_sdk::v1::EndpointAdvertisement {
                endpoint_id: "io.anchor.desktop".into(),
                capabilities: vec![anchor_sdk::v1::CapabilityAdvertisement {
                    name: "org.anchor.clipboard".into(),
                    major: 1,
                    record_type_urls: vec![anchor_sdk::clipboard::PUBLISH_TYPE_URL.into()],
                    supports_datagrams: false,
                }],
            };
            let (opened_tx, opened_rx) = oneshot::channel();
            let (completed_tx, completed_rx) = oneshot::channel();
            let server_task = tokio::spawn(async move {
                let incoming = server.accept().await.unwrap();
                let session = Session::accept(incoming, identity(vec![advertisement])).await.unwrap();
                let SessionEvent::CapabilityOpenRequested {
                    request_id,
                    capability_session_id,
                    ..
                } = session.next_event().await.unwrap()
                else {
                    panic!("expected capability open request");
                };
                opened_tx.send((request_id, capability_session_id)).unwrap();

                for event in server_interleaving {
                    match event {
                        CapabilityOpenInterleaving::Ping => session.send_ping(ping_nonce).await.unwrap(),
                        CapabilityOpenInterleaving::WrongRequest => session
                            .send_capability_opened(
                                request_id ^ wrong_request_mask,
                                capability_session_id,
                            )
                            .await
                            .unwrap(),
                        CapabilityOpenInterleaving::WrongCapability => session
                            .send_capability_opened(
                                request_id,
                                capability_session_id ^ wrong_capability_mask,
                            )
                            .await
                            .unwrap(),
                        CapabilityOpenInterleaving::Correct => session
                            .send_capability_opened(request_id, capability_session_id)
                            .await
                            .unwrap(),
                    }
                }
                let _ = completed_rx.await;
            });

            let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config);
            let client = Session::connect(
                &client_endpoint,
                address,
                "anchor.test",
                identity(vec![]),
            )
            .await
            .unwrap();
            let capability = client
                .open_capability("io.anchor.desktop", "org.anchor.clipboard", 1)
                .await
                .unwrap();
            let (request_id, capability_session_id) = opened_rx.await.unwrap();
            assert_eq!(capability.session_id(), capability_session_id);

            for event in interleaving {
                let expected = match event {
                    CapabilityOpenInterleaving::Ping => Some(SessionEvent::Ping { nonce: ping_nonce }),
                    CapabilityOpenInterleaving::WrongRequest => Some(SessionEvent::CapabilityOpened {
                        response_to: request_id ^ wrong_request_mask,
                        capability_session_id,
                    }),
                    CapabilityOpenInterleaving::WrongCapability => Some(SessionEvent::CapabilityOpened {
                        response_to: request_id,
                        capability_session_id: capability_session_id ^ wrong_capability_mask,
                    }),
                    CapabilityOpenInterleaving::Correct => None,
                };
                if let Some(expected) = expected {
                    assert_eq!(client.next_event().await.unwrap(), expected);
                }
            }

            completed_tx.send(()).unwrap();
            client.close(0, b"test complete");
            server_task.await.unwrap();
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_first_record_is_classified_and_cannot_open_capabilities() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let AcceptedSession::Pairing(pairing) =
            Session::accept_classified(incoming, identity(vec![]))
                .await
                .unwrap()
        else {
            panic!("PairingHello must not become a normal capability session");
        };
        assert_eq!(pairing.hello().display_name, "Phone");
        pairing.approve(vec![9; 32]).await.unwrap();
        // A pairing decision is a reliable control record. Keep the server
        // connection alive until the initiator observes it instead of dropping
        // the SendStream immediately after flush.
        let _ = pairing.closed().await;
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let pairing = PairingSession::connect(
        &client_endpoint,
        address,
        "anchor.test",
        anchor_sdk::pairing::Hello {
            invitation_id: vec![1; 16],
            node_id: [2; 32],
            display_name: "Phone".into(),
            device_kind: 2,
            transcript_hash: [3; 32],
        },
    )
    .await
    .unwrap();
    let anchor_sdk::v1::control_envelope::Body::PairingApprove(approve) =
        pairing.next_resolution().await.unwrap()
    else {
        panic!("expected explicit pairing approval");
    };
    assert_eq!(approve.transcript_hash, vec![9; 32]);
    pairing.close(0, b"pairing complete");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_flows_receive_only_their_own_flows_packets() {
    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::camera::endpoint_advertisement()]),
        )
        .await
        .unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            endpoint_id,
            capability_name,
            capability_major,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected capability open request");
        };
        session
            .accept_capability(
                request_id,
                capability_session_id,
                &endpoint_id,
                &capability_name,
                capability_major,
            )
            .await
            .unwrap();

        let mut flows = Vec::new();
        for _ in 0..2 {
            let SessionEvent::DatagramFlowOpenRequested {
                request_id,
                flow_id,
                ..
            } = session.next_event().await.unwrap()
            else {
                panic!("expected datagram flow open request");
            };
            flows.push(
                session
                    .accept_datagram_flow(request_id, flow_id)
                    .await
                    .unwrap(),
            );
        }
        assert_ne!(flows[0].flow_id(), flows[1].flow_id());

        // Only flow[1]'s datagrams were sent: its receiver must get a packet
        // while flow[0]'s receiver must observe nothing (no cross-flow steal).
        let delivered = timeout(Duration::from_millis(500), flows[1].recv())
            .await
            .expect("flow packets must reach their own receiver")
            .expect("flow receiver must deliver a packet");
        let (header, payload) = anchor_sdk::video_frame::FrameHeader::decode(&delivered).unwrap();
        assert_eq!(header.flow_id, flows[1].flow_id());
        assert_eq!(payload, b"flow-b");

        assert!(
            timeout(Duration::from_millis(150), flows[0].recv())
                .await
                .is_err(),
            "a flow must never observe another flow's datagrams",
        );
        session.close(0, b"test complete");
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();
    let capability = client
        .open_capability(
            anchor_sdk::camera::ENDPOINT_ID,
            anchor_sdk::camera::CAPABILITY_NAME,
            anchor_sdk::camera::CAPABILITY_MAJOR,
        )
        .await
        .unwrap();
    let _flow_a = capability
        .open_datagram_flow(anchor_sdk::camera::FRAME_TYPE_URL)
        .await
        .unwrap();
    let flow_b = capability
        .open_datagram_flow(anchor_sdk::camera::FRAME_TYPE_URL)
        .await
        .unwrap();

    // Give the accept side a moment to register its routes, then send
    // flow-b-only packets a few times to absorb loopback/race loss.
    sleep(Duration::from_millis(30)).await;
    for _ in 0..8 {
        let packets = anchor_sdk::video_frame::fragment_frame(
            anchor_sdk::video_frame::FRAME_KIND_CAMERA,
            capability.session_id(),
            flow_b.flow_id(),
            1,
            0,
            0,
            b"flow-b",
        )
        .unwrap();
        flow_b.send(packets[0].clone()).unwrap();
        sleep(Duration::from_millis(5)).await;
    }

    server_task.await.unwrap();
}

#[tokio::test]
async fn parity_recovers_a_fragment_lost_over_real_quic_datagrams() {
    use anchor_sdk::video_frame::{
        FRAME_KIND_CAMERA, FRAME_KIND_PARITY, FrameHeader, Reassembler, fragment_frame_with_parity,
    };

    let (server_config, client_config) = configs();
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::camera::endpoint_advertisement()]),
        )
        .await
        .unwrap();
        let SessionEvent::CapabilityOpenRequested {
            request_id,
            capability_session_id,
            endpoint_id,
            capability_name,
            capability_major,
        } = session.next_event().await.unwrap()
        else {
            panic!("expected capability open request");
        };
        session
            .accept_capability(
                request_id,
                capability_session_id,
                &endpoint_id,
                &capability_name,
                capability_major,
            )
            .await
            .unwrap();
        let SessionEvent::DatagramFlowOpenRequested {
            request_id,
            flow_id,
            ..
        } = session.next_event().await.unwrap()
        else {
            panic!("expected datagram flow open request");
        };
        let flow = session
            .accept_datagram_flow(request_id, flow_id)
            .await
            .unwrap();

        // Reassemble whatever datagrams arrive; one data fragment was
        // withheld by the sender, so only parity can complete the frame.
        let mut assembler = Reassembler::default();
        let frame = timeout(Duration::from_secs(5), async {
            loop {
                let datagram = flow.recv().await.expect("flow must stay open");
                if let Some(frame) = assembler.add_datagram(
                    &datagram,
                    FRAME_KIND_CAMERA,
                    capability_session_id,
                    flow_id,
                ) {
                    break frame;
                }
            }
        })
        .await
        .expect("parity must rebuild the withheld fragment within 5s");
        assert!(
            frame.iter().enumerate().all(|(i, b)| *b == (i % 239) as u8),
            "recovered frame must match byte-exact"
        );
        session.close(0, b"test complete");
    });

    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.test", identity(vec![]))
        .await
        .unwrap();
    let capability = client
        .open_capability(
            anchor_sdk::camera::ENDPOINT_ID,
            anchor_sdk::camera::CAPABILITY_NAME,
            anchor_sdk::camera::CAPABILITY_MAJOR,
        )
        .await
        .unwrap();
    let flow = capability
        .open_datagram_flow(anchor_sdk::camera::FRAME_TYPE_URL)
        .await
        .unwrap();

    let frame: Vec<u8> = (0..20 * 1024 + 13).map(|i| (i % 239) as u8).collect();
    let packets = fragment_frame_with_parity(
        FRAME_KIND_CAMERA,
        0,
        capability.session_id(),
        flow.flow_id(),
        1,
        0,
        0,
        &frame,
    )
    .unwrap();
    // Withhold data fragment 5 — simulates a single datagram lost on the
    // wire; parity for group 0 must cover it.
    let withheld = 5_usize;
    for packet in packets.iter() {
        let header = FrameHeader::decode(packet).unwrap().0;
        if header.kind != FRAME_KIND_PARITY && header.fragment_index as usize == withheld {
            continue;
        }
        flow.send(packet.clone()).unwrap();
    }
    server_task.await.unwrap();
}
