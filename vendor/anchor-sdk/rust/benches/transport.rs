//! Loopback transport benchmarks: a real QUIC session over 127.0.0.1,
//! exercising the datagram send path, the connection-level dispatcher, and
//! per-flow routing — not just the codec helpers.
use anchor_sdk::{SessionIdentity, quinn_transport, session::Session, v1, video_frame};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use quinn::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;

fn configs() -> (quinn::ServerConfig, quinn::ClientConfig) {
    let certificate = generate_simple_self_signed(vec!["anchor.bench".into()]).unwrap();
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

fn identity(endpoints: Vec<v1::EndpointAdvertisement>) -> SessionIdentity {
    SessionIdentity {
        node_id: [7; 32],
        display_name: "bench-peer".into(),
        device_kind: 1,
        endpoints,
    }
}

/// One session pair, one negotiated datagram flow, and a server-side echo
/// task that sends every received datagram straight back — so a single flow
/// measures the full routed path on both ends.
struct BenchPair {
    client_flow: anchor_sdk::session::DatagramFlow,
    capability_session_id: u64,
    _session_guard: tokio::task::JoinHandle<()>,
    _server_endpoint: Endpoint,
    _client_endpoint: Endpoint,
}

fn endpoint(config: Option<quinn::ServerConfig>, address: &str) -> Endpoint {
    let socket = quinn_transport::bind_udp_socket(address.parse().unwrap()).unwrap();
    Endpoint::new(
        quinn::EndpointConfig::default(),
        config,
        socket,
        quinn::default_runtime().unwrap(),
    )
    .unwrap()
}

async fn make_pair(rt_handle: &tokio::runtime::Handle) -> BenchPair {
    let _guard = rt_handle.enter();
    let (server_config, client_config) = configs();
    // Both endpoints ride the enlarged-buffer socket: an echo burst (~300KiB)
    // overruns the ~200KiB kernel default and drops at the socket layer.
    let server_endpoint = endpoint(Some(server_config), "127.0.0.1:0");
    let address = server_endpoint.local_addr().unwrap();
    let accept_endpoint = server_endpoint.clone();

    let server_task = tokio::spawn(async move {
        let incoming = accept_endpoint.accept().await.unwrap();
        let session = Session::accept(
            incoming,
            identity(vec![anchor_sdk::camera::endpoint_advertisement()]),
        )
        .await
        .unwrap();
        let anchor_sdk::SessionEvent::CapabilityOpenRequested {
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
        let anchor_sdk::SessionEvent::DatagramFlowOpenRequested {
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
        // Echo loop: keeps the connection alive and returns every datagram.
        // A full-frame burst arrives faster than the wire drains, so sends can
        // hit the stale-queue bound — retry like a paced production sender
        // instead of silently dropping fragments.
        while let Ok(datagram) = flow.recv().await {
            while flow.send(datagram.clone()).is_err() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    });

    let mut client_endpoint = endpoint(None, "127.0.0.1:0");
    client_endpoint.set_default_client_config(client_config);
    let client = Session::connect(&client_endpoint, address, "anchor.bench", identity(vec![]))
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
    let client_flow = capability
        .open_datagram_flow(anchor_sdk::camera::FRAME_TYPE_URL)
        .await
        .unwrap();
    // Give the server task a moment to install its route.
    tokio::time::sleep(Duration::from_millis(30)).await;

    BenchPair {
        client_flow,
        capability_session_id: capability.session_id(),
        _session_guard: server_task,
        _server_endpoint: server_endpoint,
        _client_endpoint: client_endpoint,
    }
}

fn datagram_benches(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let handle = rt.handle().clone();
    let pair = rt.block_on(make_pair(&handle));

    let mut group = c.benchmark_group("datagram_transport");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));

    // Routed round-trip needs a datagram the dispatcher can actually route:
    // a real ANFR packet carrying this flow's flow_id. A raw payload without
    // a valid header is dropped server-side and the echo never comes back.
    // A 900-byte payload fragments to a single datagram.
    let single = video_frame::fragment_frame(
        video_frame::FRAME_KIND_CAMERA,
        pair.capability_session_id,
        pair.client_flow.flow_id(),
        1,
        0,
        0,
        &vec![0u8; 900],
    )
    .unwrap()
    .into_iter()
    .next()
    .unwrap();
    group.bench_function("routed_round_trip_1frag", |b| {
        b.iter(|| {
            rt.block_on(async {
                pair.client_flow.send(single.clone()).unwrap();
                black_box(pair.client_flow.recv().await.unwrap());
            })
        })
    });

    // Whole-frame routed round-trip: fragment → send_many → wire → server
    // dispatcher → echo → client dispatcher → per-flow channel → reassembly.
    for frame_bytes in [64 * 1024, 256 * 1024] {
        group.bench_with_input(
            BenchmarkId::new("frame_round_trip", frame_bytes),
            &frame_bytes,
            |b, &frame_bytes| {
                let payload = vec![0xABu8; frame_bytes];
                let mut reassembler = video_frame::Reassembler::default();
                b.iter(|| {
                    rt.block_on(async {
                        let packets = video_frame::fragment_frame(
                            video_frame::FRAME_KIND_CAMERA,
                            pair.capability_session_id,
                            pair.client_flow.flow_id(),
                            1,
                            0,
                            0,
                            &payload,
                        )
                        .unwrap();
                        // Back-to-back iterations outpace drain: retry on the
                        // stale-queue bound the way paced production sends do.
                        while pair
                            .client_flow
                            .send_many(black_box(packets.clone()))
                            .is_err()
                        {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        loop {
                            // Bounded wait: a dropped echo must fail loudly,
                            // not hang the benchmark.
                            let datagram = tokio::time::timeout(
                                Duration::from_secs(5),
                                pair.client_flow.recv(),
                            )
                            .await
                            .expect("echo stalled — datagram lost")
                            .unwrap();
                            if let Some(frame) = reassembler.add_datagram(
                                &datagram,
                                video_frame::FRAME_KIND_CAMERA,
                                pair.capability_session_id,
                                pair.client_flow.flow_id(),
                            ) {
                                break black_box(frame);
                            }
                        }
                    })
                })
            },
        );
    }

    // Sustained throughput: a burst of frames pipelined through the routed
    // path — sends retry on the stale-queue bound instead of waiting per
    // frame, so the measurement covers admission + wire + dispatch +
    // reassembly running concurrently, not serialized RTTs.
    const BURST_FRAMES: usize = 16;
    let burst_frame_bytes = 128 * 1024;
    group.throughput(Throughput::Bytes((BURST_FRAMES * burst_frame_bytes) as u64));
    group.bench_function("burst_throughput_16x128KiB", |b| {
        let payload = vec![0xCDu8; burst_frame_bytes];
        let mut reassembler = video_frame::Reassembler::default();
        b.iter(|| {
            rt.block_on(async {
                for sequence in 0..BURST_FRAMES as u64 {
                    let packets = video_frame::fragment_frame(
                        video_frame::FRAME_KIND_CAMERA,
                        pair.capability_session_id,
                        pair.client_flow.flow_id(),
                        sequence,
                        0,
                        0,
                        &payload,
                    )
                    .unwrap();
                    while pair
                        .client_flow
                        .send_many(black_box(packets.clone()))
                        .is_err()
                    {
                        tokio::time::sleep(Duration::from_micros(200)).await;
                    }
                }
                let mut frames_done = 0usize;
                while frames_done < BURST_FRAMES {
                    let datagram =
                        tokio::time::timeout(Duration::from_secs(10), pair.client_flow.recv())
                            .await
                            .expect("burst echo stalled — datagram lost")
                            .unwrap();
                    if reassembler
                        .add_datagram(
                            &datagram,
                            video_frame::FRAME_KIND_CAMERA,
                            pair.capability_session_id,
                            pair.client_flow.flow_id(),
                        )
                        .is_some()
                    {
                        frames_done += 1;
                    }
                }
            })
        })
    });
    group.finish();
}

criterion_group!(benches, datagram_benches);
criterion_main!(benches);
