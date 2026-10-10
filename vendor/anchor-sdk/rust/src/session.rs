//! High-level Anchor session lifecycle over a caller-owned Quinn endpoint.
//!
//! `Session` owns the authenticated control stream and its framing. Callers
//! never need to know which protobuf record is the first record, how the
//! length prefix is encoded, or how a session ID is allocated. Capability
//! providers still own their application policy; an incoming capability-open
//! request is surfaced as an event and is never approved implicitly.

use rustc_hash::FxHashMap;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use prost::Message;
use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

use crate::{
    ALPN, CONTROL_MAGIC, MAX_CONTROL_RECORD_BYTES, NODE_ID_BYTES, PROTOCOL_MAJOR, PROTOCOL_MINOR,
    ProtocolViolation, pairing, v1, validate_control_envelope,
};

const FIRST_RECORD_HEADER_BYTES: usize = CONTROL_MAGIC.len() + 2;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC connect failed: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC stream read failed: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("QUIC stream ended before a complete record was available: {0}")]
    ReadExact(#[from] quinn::ReadExactError),
    #[error("control framing read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("QUIC stream write failed: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC stream closed before its send side could finish: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("protocol validation failed: {0}")]
    Protocol(#[from] ProtocolViolation),
    #[error("control record is not valid in this session phase: {0}")]
    UnexpectedRecord(&'static str),
    #[error("peer does not advertise capability {name}@{major}")]
    CapabilityUnavailable { name: String, major: u32 },
    #[error("peer did not acknowledge capability session {0}")]
    CapabilityNotOpened(u64),
    #[error("control stream ended")]
    ControlStreamEnded,
    #[error("datagram flow ended")]
    DatagramFlowEnded,
}

/// Local identity and endpoint advertisements sent in `SessionHello`.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionIdentity {
    pub node_id: [u8; NODE_ID_BYTES],
    pub display_name: String,
    pub device_kind: i32,
    pub endpoints: Vec<v1::EndpointAdvertisement>,
}

impl SessionIdentity {
    fn hello(&self) -> v1::ControlEnvelope {
        v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(v1::control_envelope::Body::SessionHello(v1::SessionHello {
                protocol_version: Some(v1::ProtocolVersion {
                    major: u32::from(PROTOCOL_MAJOR),
                    minor: u32::from(PROTOCOL_MINOR),
                }),
                node_id: Some(v1::NodeId {
                    value: self.node_id.to_vec(),
                }),
                display: Some(v1::PeerDisplayInfo {
                    display_name: self.display_name.clone(),
                    device_kind: self.device_kind,
                }),
                endpoints: self.endpoints.clone(),
            })),
        }
    }
}

/// The authenticated peer's advertised identity and capability catalog.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionPeer {
    pub node_id: [u8; NODE_ID_BYTES],
    pub display_name: String,
    pub device_kind: i32,
    pub endpoints: Vec<v1::EndpointAdvertisement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionRole {
    Initiator,
}

/// Events that remain after the session handshake. Application policy must
/// explicitly handle `CapabilityOpenRequested`; the SDK never grants access
/// merely because a peer is authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    CapabilityOpenRequested {
        request_id: u64,
        capability_session_id: u64,
        endpoint_id: String,
        capability_name: String,
        capability_major: u32,
    },
    CapabilityOpened {
        response_to: u64,
        capability_session_id: u64,
    },
    CapabilityClosed {
        capability_session_id: u64,
        reason: i32,
    },
    CapabilityRecord {
        capability_session_id: u64,
        type_url: String,
        payload: Vec<u8>,
    },
    StreamOpenRequested {
        request_id: u64,
        quic_stream_id: u64,
        capability_session_id: u64,
        payload_type_url: String,
    },
    StreamOpened {
        response_to: u64,
        quic_stream_id: u64,
    },
    StreamClosed {
        quic_stream_id: u64,
    },
    DatagramFlowOpenRequested {
        request_id: u64,
        capability_session_id: u64,
        flow_id: u64,
        payload_type_url: String,
    },
    DatagramFlowOpened {
        response_to: u64,
        flow_id: u64,
    },
    DatagramFlowClosed {
        flow_id: u64,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    ProtocolError {
        response_to: u64,
        code: i32,
        message: String,
    },
    SessionClosed {
        reason: i32,
    },
}

/// A negotiated capability session. It validates record type URLs against the
/// peer's advertisement before anything reaches the wire.
#[derive(Clone)]
pub struct Capability {
    session: Session,
    session_id: u64,
    allowed_type_urls: Arc<Vec<String>>,
    supports_datagrams: bool,
}

#[derive(Clone)]
struct CapabilityState {
    allowed_type_urls: Arc<Vec<String>>,
    supports_datagrams: bool,
    open: bool,
}

/// A capability-bound reliable QUIC stream.
///
/// The SDK owns the raw Quinn handles and the required `StreamOpen` protocol
/// exchange. Hosts receive only the negotiated stream ID and byte reader/
/// writer wrappers.
pub struct ReliableStream {
    stream_id: u64,
    send: ReliableSendStream,
    recv: ReliableRecvStream,
}

pub struct ReliableSendStream {
    stream_id: u64,
    inner: quinn::SendStream,
}

pub struct ReliableRecvStream {
    stream_id: u64,
    inner: quinn::RecvStream,
}

impl ReliableStream {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn into_parts(self) -> (ReliableSendStream, ReliableRecvStream) {
        (self.send, self.recv)
    }
}

impl ReliableSendStream {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        self.inner
            .write_all(bytes)
            .await
            .map_err(SessionError::Write)
    }

    /// Writes every chunk without concatenating them first. Producers that
    /// already hold `Bytes` fragments (for example ANFR packets with their
    /// stream length prefixes) avoid a per-frame copy through an intermediate
    /// buffer.
    pub async fn write_all_chunks(&mut self, bufs: &mut [Bytes]) -> Result<(), SessionError> {
        self.inner
            .write_all_chunks(bufs)
            .await
            .map_err(SessionError::Write)
    }

    pub fn finish(&mut self) -> Result<(), SessionError> {
        self.inner.finish().map_err(SessionError::ClosedStream)
    }
}

impl ReliableRecvStream {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub async fn read_chunk(
        &mut self,
        max_size: usize,
        ordered: bool,
    ) -> Result<Option<Bytes>, SessionError> {
        self.inner
            .read_chunk(max_size, ordered)
            .await
            .map(|chunk| chunk.map(|chunk| chunk.bytes))
            .map_err(SessionError::Read)
    }
}

impl Capability {
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub async fn send_record(
        &self,
        type_url: &str,
        payload: impl Into<Vec<u8>>,
    ) -> Result<(), SessionError> {
        self.session
            .ensure_capability_open(self.session_id, type_url, false)
            .await?;
        if !self
            .allowed_type_urls
            .iter()
            .any(|allowed| allowed == type_url)
        {
            return Err(SessionError::UnexpectedRecord(
                "record type URL was not advertised",
            ));
        }
        self.session
            .send(v1::control_envelope::Body::CapabilityRecord(
                v1::CapabilityRecord {
                    capability_session_id: self.session_id,
                    type_url: type_url.to_owned(),
                    payload: payload.into(),
                },
            ))
            .await
    }

    /// Negotiates a replaceable QUIC datagram flow for this capability.
    pub async fn open_datagram_flow(
        &self,
        payload_type_url: &str,
    ) -> Result<DatagramFlow, SessionError> {
        self.session
            .ensure_capability_open(self.session_id, payload_type_url, true)
            .await?;
        if !self.supports_datagrams {
            return Err(SessionError::UnexpectedRecord(
                "capability does not advertise datagrams",
            ));
        }
        if !self
            .allowed_type_urls
            .iter()
            .any(|allowed| allowed == payload_type_url)
        {
            return Err(SessionError::UnexpectedRecord(
                "datagram type URL was not advertised",
            ));
        }
        let flow_id = self.session.allocate_flow_id();
        let request_id = self.session.allocate_request_id();
        self.session
            .send_with_request(
                request_id,
                v1::control_envelope::Body::DatagramFlowOpen(v1::DatagramFlowOpen {
                    capability_session_id: self.session_id,
                    flow_id,
                    payload_type_url: payload_type_url.to_owned(),
                }),
            )
            .await?;
        self.session
            .wait_for_event(|event| {
                matches!(event, SessionEvent::DatagramFlowOpened {
                response_to, flow_id: opened
            } if *response_to == request_id && *opened == flow_id)
            })
            .await?;
        Ok(DatagramFlow {
            session: self.session.clone(),
            flow_id,
            recv: Arc::new(Mutex::new(self.session.route_datagram_flow(flow_id))),
        })
    }

    /// Opens a reliable bidirectional stream bound to this capability. The
    /// returned stream is ready for application bytes only after the required
    /// `StreamOpen`/`StreamOpened` control exchange succeeds.
    pub async fn open_stream(
        &self,
        payload_type_url: &str,
    ) -> Result<ReliableStream, SessionError> {
        self.session
            .ensure_capability_open(self.session_id, payload_type_url, false)
            .await?;
        if !self
            .allowed_type_urls
            .iter()
            .any(|allowed| allowed == payload_type_url)
        {
            return Err(SessionError::UnexpectedRecord(
                "stream type URL was not advertised",
            ));
        }
        let (send, recv) = self.session.0.connection.open_bi().await?;
        let stream_id = u64::from(send.id());
        let request_id = self.session.allocate_request_id();
        self.session
            .send_with_request(
                request_id,
                v1::control_envelope::Body::StreamOpen(v1::StreamOpen {
                    quic_stream_id: stream_id,
                    capability_session_id: self.session_id,
                    payload_type_url: payload_type_url.to_owned(),
                }),
            )
            .await?;
        self.session
            .wait_for_event(|event| {
                matches!(event, SessionEvent::StreamOpened {
                response_to, quic_stream_id
            } if *response_to == request_id && *quic_stream_id == stream_id)
            })
            .await?;
        Ok(ReliableStream {
            stream_id,
            send: ReliableSendStream {
                stream_id,
                inner: send,
            },
            recv: ReliableRecvStream {
                stream_id,
                inner: recv,
            },
        })
    }
}

/// A negotiated unreliable datagram path associated with one capability.
///
/// Received datagrams arrive through the connection-level dispatcher, which
/// routes by the ANFR flow ID — so concurrent flows can never steal each
/// other's packets the way multiple `connection.read_datagram()` callers
/// would.
#[derive(Clone)]
pub struct DatagramFlow {
    session: Session,
    flow_id: u64,
    recv: Arc<Mutex<tokio::sync::mpsc::Receiver<Bytes>>>,
}

/// Failure returned when an application datagram cannot be queued without
/// re-entering Quinn's lossy `send_datagram` overflow path.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DatagramSendError {
    /// The connection's queue is busy. Callers carrying replaceable media
    /// should drop the current access unit and wait for the next one.
    #[error("datagram send buffer is full (available={available} required={required})")]
    BufferFull { available: usize, required: usize },
    /// The underlying transport rejected the datagram or the session closed.
    #[error("QUIC datagram send failed: {0}")]
    Transport(String),
}

/// Connection-wide counters suitable for host diagnostics and media policy.
/// This intentionally exposes Anchor values rather than Quinn implementation
/// types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatagramTransportStats {
    pub rtt: std::time::Duration,
    pub congestion_window_bytes: u64,
    pub lost_packets: u64,
    pub congestion_events: u64,
}

// Quinn 0.11's lossy send path has a queue-accounting bug when it evicts old
// datagrams after the configured buffer fills. Keep a small reserve so Anchor
// never asks Quinn to perform that eviction. The per-fragment allowance
// below accounts for Quinn's private `Datagram` bookkeeping; the public
// `datagram_send_buffer_space()` API only subtracts one such item.
const DATAGRAM_QUEUE_HEADROOM_BYTES: usize = 16 * 1024;
const DATAGRAM_QUEUE_ITEM_BYTES: usize = 32;
/// Staleness bound for the unreliable media queue, expressed as a drain time:
/// a burst may never leave more than ~40 ms of backlog waiting behind
/// congestion, so scene changes cannot stack stale frames ahead of the live
/// one. A fixed byte bound would admit ~4 ms of backlog on a fast LAN but
/// ~105 ms on a 20 Mbps uplink; scaling by the congestion controller's own
/// pacing estimate (cwnd/RTT) keeps the *time* bound constant across paths.
/// The byte bound is clamped between a small floor — so an idle queue always
/// admits the next frame — and the previous fixed cap. Quinn's buffer itself
/// is sized for the largest legal access unit (`DATAGRAM_SEND_BUFFER_BYTES`).
const DATAGRAM_STALE_QUEUE_MAX: std::time::Duration = std::time::Duration::from_millis(40);
const DATAGRAM_STALE_QUEUE_MIN_BYTES: usize = 32 * 1024;
const DATAGRAM_STALE_QUEUE_BYTES: usize = 256 * 1024;

impl DatagramFlow {
    pub fn flow_id(&self) -> u64 {
        self.flow_id
    }

    /// Current transport counters for diagnostics and adaptive media policy.
    /// These are connection-wide because QUIC congestion control and the
    /// datagram queue are shared by every capability flow.
    pub fn transport_stats(&self) -> DatagramTransportStats {
        let stats = self.session.0.connection.stats();
        DatagramTransportStats {
            rtt: stats.path.rtt,
            congestion_window_bytes: stats.path.cwnd,
            lost_packets: stats.path.lost_packets,
            congestion_events: stats.path.congestion_events,
        }
    }

    /// Current number of application-datagram bytes Quinn can accept.
    pub fn send_buffer_space(&self) -> usize {
        self.session.0.connection.datagram_send_buffer_space()
    }

    /// Maximum application payload accepted by the peer on the current path.
    /// This value can change after path-MTU discovery or network migration.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.session.0.connection.max_datagram_size()
    }

    pub fn send(&self, payload: Bytes) -> Result<(), DatagramSendError> {
        self.session.send_datagram(payload)
    }

    /// Queue a complete replaceable access unit while holding the
    /// connection-wide datagram lock. This prevents screen/camera producers
    /// from interleaving fragments and, importantly, avoids queueing a partial
    /// frame when there is not enough space for all of its fragments.
    ///
    /// Takes the packet vector by value so each fragment's `Bytes` moves into
    /// the send queue — no per-fragment refcount churn on large keyframes.
    pub fn send_many(&self, payloads: Vec<Bytes>) -> Result<(), DatagramSendError> {
        self.session.send_datagrams_owned(payloads)
    }

    /// Receive the next application datagram routed to this flow. The
    /// dispatcher only forwards packets whose ANFR flow ID matches; the
    /// per-flow queue is bounded, so a stalled consumer drops rather than
    /// accumulating stale media.
    pub async fn recv(&self) -> Result<Bytes, SessionError> {
        self.recv
            .lock()
            .await
            .recv()
            .await
            .ok_or(SessionError::DatagramFlowEnded)
    }

    pub async fn close(&self) -> Result<(), SessionError> {
        self.session
            .0
            .datagram_routes
            .lock()
            .unwrap()
            .remove(&self.flow_id);
        self.session.send_datagram_flow_closed(self.flow_id).await
    }
}

struct SessionInner {
    connection: quinn::Connection,
    // Quinn's datagram queue is connection-scoped. Serialize submissions
    // from independent screen/camera producers so queue accounting remains
    // consistent when both flows are active at once.
    datagram_send: std::sync::Mutex<()>,
    // Receiving is connection-scoped too: one dispatcher task reads
    // `read_datagram` and routes each packet to its flow's channel by the
    // ANFR flow ID. Without it, two concurrent `DatagramFlow::recv` callers
    // would steal each other's datagrams and drop them as wrong-flow.
    datagram_routes: std::sync::Mutex<FxHashMap<u64, tokio::sync::mpsc::Sender<Bytes>>>,
    datagram_dispatch_started: std::sync::atomic::AtomicBool,
    control_send: Mutex<quinn::SendStream>,
    control_recv: Mutex<ControlReader>,
    event_wait: Mutex<()>,
    queued_events: Mutex<VecDeque<SessionEvent>>,
    capabilities: Mutex<HashMap<u64, CapabilityState>>,
    next_request_id: AtomicU64,
    next_capability_id: AtomicU64,
    next_flow_id: AtomicU64,
    peer: SessionPeer,
    local_endpoints: Vec<v1::EndpointAdvertisement>,
}

/// An authenticated, protocol-ready Anchor session.
#[derive(Clone)]
pub struct Session(Arc<SessionInner>);

/// A pairing-only control stream. It deliberately has no capability, stream,
/// or datagram APIs: callers can only resolve the pending enrollment.
pub struct PairingSession {
    connection: quinn::Connection,
    control_send: Mutex<quinn::SendStream>,
    control_recv: Mutex<ControlReader>,
    hello: pairing::Hello,
}

/// The first control record determines the connection phase. A peer cannot
/// smuggle a pairing request into a normal session or vice versa.
pub enum AcceptedSession {
    Session(Session),
    Pairing(Box<PairingSession>),
}

impl PairingSession {
    /// Opens a pairing-only QUIC control stream. The caller configures the
    /// endpoint with the invitation's certificate pin before calling this.
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        address: SocketAddr,
        server_name: &str,
        hello: pairing::Hello,
    ) -> Result<Self, SessionError> {
        let connection = endpoint.connect(address, server_name)?.await?;
        validate_alpn(&connection)?;
        let (mut send, recv) = connection.open_bi().await?;
        let envelope = v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(v1::control_envelope::Body::PairingHello(hello.to_wire())),
        };
        write_record(&mut send, &envelope, true).await?;
        Ok(Self {
            connection,
            control_send: Mutex::new(send),
            control_recv: Mutex::new(ControlReader::new(recv)),
            hello,
        })
    }

    pub fn hello(&self) -> &pairing::Hello {
        &self.hello
    }

    /// Returns the peer leaf certificate DER for host enrollment policy.
    pub fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        peer_certificate_der(&self.connection)
    }

    /// End this pairing-only connection without exposing the QUIC handle.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.connection.close(code.into(), reason);
    }

    /// Wait until the peer closes this pairing-only connection.
    pub async fn closed(&self) {
        let _ = self.connection.closed().await;
    }

    pub async fn approve(&self, transcript_hash: Vec<u8>) -> Result<(), SessionError> {
        self.approve_with_identity(transcript_hash, Vec::new(), String::new())
            .await
    }

    /// Resolves enrollment and returns the exact server certificate when the
    /// initiator deliberately used a direct-address bootstrap. Normal pinned
    /// pairing receives the same fields but does not need to consume them.
    pub async fn approve_with_identity(
        &self,
        transcript_hash: Vec<u8>,
        certificate_der: Vec<u8>,
        device_id: String,
    ) -> Result<(), SessionError> {
        if certificate_der.len() > 4096 {
            return Err(SessionError::UnexpectedRecord(
                "pairing certificate exceeds 4096 bytes",
            ));
        }
        self.send_resolution(v1::control_envelope::Body::PairingApprove(
            v1::PairingApprove {
                transcript_hash,
                approver_certificate_der: certificate_der,
                approver_device_id: device_id,
            },
        ))
        .await
    }

    pub async fn reject(&self) -> Result<(), SessionError> {
        self.send_resolution(v1::control_envelope::Body::PairingReject(
            v1::PairingReject {},
        ))
        .await
    }

    async fn send_resolution(&self, body: v1::control_envelope::Body) -> Result<(), SessionError> {
        let envelope = v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(body),
        };
        let mut send = self.control_send.lock().await;
        // This is the responder's first control record, so it carries its own
        // direction-local ANCR preface even though the initiator already sent
        // one on the reverse half of the QUIC stream.
        write_record(&mut send, &envelope, true).await
    }

    /// Wait for the remote enrollment decision. This is used by a pairing
    /// initiator after presenting its local approval UI.
    pub async fn next_resolution(&self) -> Result<v1::control_envelope::Body, SessionError> {
        let mut recv = self.control_recv.lock().await;
        let envelope = recv.read_record().await?;
        match envelope.body {
            Some(body @ v1::control_envelope::Body::PairingApprove(_))
            | Some(body @ v1::control_envelope::Body::PairingReject(_)) => Ok(body),
            _ => Err(SessionError::UnexpectedRecord(
                "expected pairing resolution",
            )),
        }
    }
}

impl Session {
    /// Connects to a peer using the endpoint's configured, pinned Quinn client
    /// config. `server_name` is the certificate name, not a routing identity.
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        address: SocketAddr,
        server_name: &str,
        local: SessionIdentity,
    ) -> Result<Self, SessionError> {
        let connection = endpoint.connect(address, server_name)?.await?;
        Self::establish(connection, local, SessionRole::Initiator).await
    }

    /// Accepts an incoming Quinn connection. The caller should perform its
    /// certificate-pin decision in the endpoint's TLS verifier before passing
    /// the `Incoming` handle here.
    pub async fn accept(
        incoming: quinn::Incoming,
        local: SessionIdentity,
    ) -> Result<Self, SessionError> {
        match Self::accept_classified(incoming, local).await? {
            AcceptedSession::Session(session) => Ok(session),
            AcceptedSession::Pairing(_) => Err(SessionError::UnexpectedRecord(
                "pairing connection passed to normal session acceptor",
            )),
        }
    }

    /// Accepts a connection after classifying its first control record. Hosts
    /// must route `Pairing` to an explicit user-approval flow.
    pub async fn accept_classified(
        incoming: quinn::Incoming,
        local: SessionIdentity,
    ) -> Result<AcceptedSession, SessionError> {
        let connection = incoming.await?;
        validate_alpn(&connection)?;
        let (send, mut reader) = {
            let (send, recv) = connection.accept_bi().await?;
            (send, ControlReader::new(recv))
        };
        let first = reader.read_record().await?;
        match first.body.as_ref() {
            Some(v1::control_envelope::Body::PairingHello(hello)) => {
                let hello = pairing::Hello::from_wire(hello)?;
                Ok(AcceptedSession::Pairing(Box::new(PairingSession {
                    connection,
                    control_send: Mutex::new(send),
                    control_recv: Mutex::new(reader),
                    hello,
                })))
            }
            Some(v1::control_envelope::Body::SessionHello(_)) => Ok(AcceptedSession::Session(
                Self::establish_responder(connection, local, send, reader, first).await?,
            )),
            _ => Err(SessionError::UnexpectedRecord(
                "first control record must be SessionHello or PairingHello",
            )),
        }
    }

    pub fn peer(&self) -> &SessionPeer {
        // The peer is immutable for the lifetime of a QUIC connection. This
        // accessor avoids forcing callers to clone metadata for every event.
        &self.0.peer
    }

    /// Returns the peer leaf certificate DER after the QUIC/TLS handshake.
    /// Host pairing policy may compare it to its own persisted certificate pin.
    pub fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        peer_certificate_der(&self.0.connection)
    }

    /// End this session without exposing the underlying QUIC connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.0.connection.close(code.into(), reason);
    }

    /// Reads and validates the next control event. Only one task should call
    /// this at a time; concurrent writers are supported by the session mutex.
    pub async fn next_event(&self) -> Result<SessionEvent, SessionError> {
        if let Some(event) = self.0.queued_events.lock().await.pop_front() {
            return Ok(event);
        }
        self.read_event().await
    }

    async fn read_event(&self) -> Result<SessionEvent, SessionError> {
        let mut reader = self.0.control_recv.lock().await;
        let envelope = reader.read_record().await?;
        let event = decode_event(envelope)?;
        self.validate_incoming_event(&event).await?;
        Ok(event)
    }

    async fn wait_for_event<F>(&self, matches: F) -> Result<SessionEvent, SessionError>
    where
        F: Fn(&SessionEvent) -> bool,
    {
        let _wait = self.0.event_wait.lock().await;
        loop {
            let queued = {
                let mut events = self.0.queued_events.lock().await;
                events
                    .iter()
                    .position(&matches)
                    .and_then(|index| events.remove(index))
            };
            if let Some(event) = queued {
                return Ok(event);
            }
            let event = self.read_event().await?;
            if matches(&event) {
                return Ok(event);
            }
            self.0.queued_events.lock().await.push_back(event);
        }
    }

    async fn ensure_capability_open(
        &self,
        capability_session_id: u64,
        type_url: &str,
        requires_datagrams: bool,
    ) -> Result<(), SessionError> {
        let capabilities = self.0.capabilities.lock().await;
        let state = capabilities
            .get(&capability_session_id)
            .filter(|state| state.open)
            .ok_or(SessionError::UnexpectedRecord(
                "capability session is not open",
            ))?;
        if !state
            .allowed_type_urls
            .iter()
            .any(|allowed| allowed == type_url)
        {
            return Err(SessionError::UnexpectedRecord(
                "record type URL was not advertised",
            ));
        }
        if requires_datagrams && !state.supports_datagrams {
            return Err(SessionError::UnexpectedRecord(
                "capability does not advertise datagrams",
            ));
        }
        Ok(())
    }

    async fn validate_incoming_event(&self, event: &SessionEvent) -> Result<(), SessionError> {
        match event {
            SessionEvent::CapabilityRecord {
                capability_session_id,
                type_url,
                ..
            } => {
                self.ensure_capability_open(*capability_session_id, type_url, false)
                    .await
            }
            SessionEvent::CapabilityClosed {
                capability_session_id,
                ..
            } => {
                let mut capabilities = self.0.capabilities.lock().await;
                let state = capabilities
                    .get_mut(capability_session_id)
                    .ok_or(SessionError::UnexpectedRecord("unknown capability session"))?;
                state.open = false;
                Ok(())
            }
            SessionEvent::DatagramFlowOpenRequested {
                capability_session_id,
                payload_type_url,
                ..
            } => {
                self.ensure_capability_open(*capability_session_id, payload_type_url, true)
                    .await
            }
            _ => Ok(()),
        }
    }

    /// Opens a peer-advertised capability and waits for its positive reply.
    /// Unrelated events are preserved for the next `next_event` call.
    pub async fn open_capability(
        &self,
        endpoint_id: &str,
        capability_name: &str,
        capability_major: u32,
    ) -> Result<Capability, SessionError> {
        let advertisement = self
            .peer()
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == endpoint_id)
            .and_then(|endpoint| {
                endpoint.capabilities.iter().find(|capability| {
                    capability.name == capability_name && capability.major == capability_major
                })
            })
            .ok_or_else(|| SessionError::CapabilityUnavailable {
                name: capability_name.to_owned(),
                major: capability_major,
            })?;
        let capability_session_id = self.allocate_capability_id();
        let request_id = self.allocate_request_id();
        self.send_with_request(
            request_id,
            v1::control_envelope::Body::CapabilityOpen(v1::CapabilityOpen {
                capability_session_id,
                endpoint_id: endpoint_id.to_owned(),
                capability_name: capability_name.to_owned(),
                capability_major,
            }),
        )
        .await?;

        self.wait_for_event(|event| {
            matches!(event, SessionEvent::CapabilityOpened {
            response_to, capability_session_id: opened
        } if *response_to == request_id && *opened == capability_session_id)
        })
        .await?;
        let state = CapabilityState {
            allowed_type_urls: Arc::new(advertisement.record_type_urls.clone()),
            supports_datagrams: advertisement.supports_datagrams,
            open: true,
        };
        self.0
            .capabilities
            .lock()
            .await
            .insert(capability_session_id, state.clone());
        Ok(Capability {
            session: self.clone(),
            session_id: capability_session_id,
            allowed_type_urls: state.allowed_type_urls,
            supports_datagrams: state.supports_datagrams,
        })
    }

    /// Sends a typed control record for a capability after the host has
    /// approved an incoming request. The approval policy is intentionally
    /// outside the connection object.
    pub async fn send_capability_opened(
        &self,
        request_id: u64,
        capability_session_id: u64,
    ) -> Result<(), SessionError> {
        self.send_response(
            request_id,
            v1::control_envelope::Body::CapabilityOpened(v1::CapabilityOpened {
                capability_session_id,
            }),
        )
        .await
    }

    /// Approves an incoming capability request and returns the provider-side
    /// handle for sending records back on that negotiated session.
    pub async fn accept_capability(
        &self,
        request_id: u64,
        capability_session_id: u64,
        endpoint_id: &str,
        capability_name: &str,
        capability_major: u32,
    ) -> Result<Capability, SessionError> {
        let advertisement = self
            .0
            .local_endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == endpoint_id)
            .and_then(|endpoint| {
                endpoint.capabilities.iter().find(|capability| {
                    capability.name == capability_name && capability.major == capability_major
                })
            })
            .ok_or_else(|| SessionError::CapabilityUnavailable {
                name: capability_name.to_owned(),
                major: capability_major,
            })?;
        let state = CapabilityState {
            allowed_type_urls: Arc::new(advertisement.record_type_urls.clone()),
            supports_datagrams: advertisement.supports_datagrams,
            open: true,
        };
        self.0
            .capabilities
            .lock()
            .await
            .insert(capability_session_id, state.clone());
        self.send_capability_opened(request_id, capability_session_id)
            .await?;
        Ok(Capability {
            session: self.clone(),
            session_id: capability_session_id,
            allowed_type_urls: state.allowed_type_urls,
            supports_datagrams: state.supports_datagrams,
        })
    }

    pub async fn send_stream_opened(
        &self,
        request_id: u64,
        quic_stream_id: u64,
    ) -> Result<(), SessionError> {
        self.send_response(
            request_id,
            v1::control_envelope::Body::StreamOpened(v1::StreamOpened { quic_stream_id }),
        )
        .await
    }

    /// Accept a peer-requested capability stream. The SDK rejects IDs that
    /// cannot name a peer-initiated bidirectional stream, then verifies that
    /// the accepted QUIC stream ID matches the negotiated ID before returning
    /// application byte handles.
    pub async fn accept_stream(
        &self,
        request_id: u64,
        expected_stream_id: u64,
    ) -> Result<ReliableStream, SessionError> {
        if expected_stream_id == 0
            || expected_stream_id > (1_u64 << 62) - 1
            || expected_stream_id & 0b11 != 0
        {
            return Err(SessionError::UnexpectedRecord(
                "StreamOpen did not name a client-initiated bidirectional stream",
            ));
        }
        self.send_stream_opened(request_id, expected_stream_id)
            .await?;
        let (send, recv) = self.0.connection.accept_bi().await?;
        let stream_id = u64::from(recv.id());
        if stream_id != expected_stream_id {
            return Err(SessionError::UnexpectedRecord(
                "accepted QUIC stream ID did not match StreamOpen",
            ));
        }
        Ok(ReliableStream {
            stream_id,
            send: ReliableSendStream {
                stream_id,
                inner: send,
            },
            recv: ReliableRecvStream {
                stream_id,
                inner: recv,
            },
        })
    }

    pub async fn send_capability_closed(
        &self,
        capability_session_id: u64,
        reason: i32,
    ) -> Result<(), SessionError> {
        self.send(v1::control_envelope::Body::CapabilityClose(
            v1::CapabilityClose {
                capability_session_id,
                reason,
            },
        ))
        .await
    }

    pub async fn send_stream_closed(&self, quic_stream_id: u64) -> Result<(), SessionError> {
        self.send(v1::control_envelope::Body::StreamClose(v1::StreamClose {
            quic_stream_id,
        }))
        .await
    }

    pub async fn send_datagram_flow_opened(
        &self,
        request_id: u64,
        flow_id: u64,
    ) -> Result<(), SessionError> {
        self.send_response(
            request_id,
            v1::control_envelope::Body::DatagramFlowOpened(v1::DatagramFlowOpened { flow_id }),
        )
        .await
    }

    /// Accept a peer-requested datagram flow after the application has
    /// checked the capability session and payload type.
    pub async fn accept_datagram_flow(
        &self,
        request_id: u64,
        flow_id: u64,
    ) -> Result<DatagramFlow, SessionError> {
        self.send_datagram_flow_opened(request_id, flow_id).await?;
        Ok(DatagramFlow {
            session: self.clone(),
            flow_id,
            recv: Arc::new(Mutex::new(self.route_datagram_flow(flow_id))),
        })
    }

    pub async fn send_datagram_flow_closed(&self, flow_id: u64) -> Result<(), SessionError> {
        self.send(v1::control_envelope::Body::DatagramFlowClose(
            v1::DatagramFlowClose { flow_id },
        ))
        .await
    }

    pub async fn send_ping(&self, nonce: u64) -> Result<(), SessionError> {
        self.send(v1::control_envelope::Body::Ping(v1::Ping { nonce }))
            .await
    }

    pub async fn send_pong(&self, nonce: u64) -> Result<(), SessionError> {
        self.send(v1::control_envelope::Body::Pong(v1::Pong { nonce }))
            .await
    }

    /// Sends an application datagram. Flow negotiation and the capability's
    /// fixed binary header remain explicit at the capability layer.
    pub fn send_datagram(&self, payload: Bytes) -> Result<(), DatagramSendError> {
        self.send_datagrams(std::slice::from_ref(&payload))
    }

    /// Register a receive route for one datagram flow and lazily start the
    /// connection-level dispatcher. Each route is a bounded channel: a full
    /// queue drops the datagram, preserving QUIC's lossy semantics for media
    /// without letting a stalled consumer grow unbounded.
    fn route_datagram_flow(&self, flow_id: u64) -> tokio::sync::mpsc::Receiver<Bytes> {
        // Room for one whole maximum-size access unit (~8007 fragments at
        // MAX_FRAME_BYTES) plus slack: anything smaller can be dropped
        // mid-frame only by a genuinely stalled consumer. The channel grows
        // by allocation chunks, so the bound costs nothing while queues stay
        // short.
        const DATAGRAM_ROUTE_CAPACITY: usize = 8192;
        let (tx, rx) = tokio::sync::mpsc::channel(DATAGRAM_ROUTE_CAPACITY);
        self.0
            .datagram_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(flow_id, tx);
        if !self
            .0
            .datagram_dispatch_started
            .swap(true, Ordering::AcqRel)
        {
            tokio::spawn(dispatch_datagrams(self.clone()));
        }
        rx
    }

    fn send_datagrams(&self, payloads: &[Bytes]) -> Result<(), DatagramSendError> {
        if payloads.is_empty() {
            return Ok(());
        }
        let _guard = self
            .0
            .datagram_send
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let available = self.0.connection.datagram_send_buffer_space();
        let required = payloads
            .iter()
            .map(|payload| payload.len().saturating_add(DATAGRAM_QUEUE_ITEM_BYTES))
            .sum::<usize>()
            .saturating_add(DATAGRAM_QUEUE_HEADROOM_BYTES);
        if self.datagram_admission_denied(available, required) {
            return Err(DatagramSendError::BufferFull {
                available,
                required,
            });
        }
        for payload in payloads {
            self.0
                .connection
                .send_datagram(payload.clone())
                .map_err(|error| DatagramSendError::Transport(error.to_string()))?;
        }
        Ok(())
    }

    /// All-or-nothing admission: the burst must physically fit in Quinn's
    /// queue, and the backlog already waiting there must not exceed the
    /// staleness bound. Oversized access units are not special-cased — they
    /// pass as soon as congestion drains the backlog under the bound, which
    /// is also what keeps a huge keyframe from starving forever.
    fn datagram_admission_denied(&self, available: usize, required: usize) -> bool {
        if required > available {
            return true;
        }
        let queued = crate::quinn_transport::DATAGRAM_SEND_BUFFER_BYTES.saturating_sub(available);
        // The staleness bound is clamped below by STALE_QUEUE_MIN_BYTES, so a
        // backlog at or under that floor can never deny — skip the stats
        // snapshot entirely on an empty or near-empty queue.
        if queued <= DATAGRAM_STALE_QUEUE_MIN_BYTES {
            return false;
        }
        let stats = self.0.connection.stats();
        // cwnd/RTT approximates the pacing rate congestion control is
        // enforcing right now; backlog beyond ~40 ms of drain time is stale.
        let rate_bps = stats.path.cwnd as f64 / stats.path.rtt.as_secs_f64().max(1e-6);
        let bound = (rate_bps * DATAGRAM_STALE_QUEUE_MAX.as_secs_f64()) as usize;
        queued > bound.clamp(DATAGRAM_STALE_QUEUE_MIN_BYTES, DATAGRAM_STALE_QUEUE_BYTES)
    }

    /// Owned-packet variant of `send_datagrams`: identical admission logic,
    /// but each `Bytes` moves into Quinn's queue instead of taking a refcount.
    fn send_datagrams_owned(&self, payloads: Vec<Bytes>) -> Result<(), DatagramSendError> {
        if payloads.is_empty() {
            return Ok(());
        }
        let _guard = self
            .0
            .datagram_send
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let available = self.0.connection.datagram_send_buffer_space();
        let required = payloads
            .iter()
            .map(|payload| payload.len().saturating_add(DATAGRAM_QUEUE_ITEM_BYTES))
            .sum::<usize>()
            .saturating_add(DATAGRAM_QUEUE_HEADROOM_BYTES);
        if self.datagram_admission_denied(available, required) {
            return Err(DatagramSendError::BufferFull {
                available,
                required,
            });
        }
        for payload in payloads {
            self.0
                .connection
                .send_datagram(payload)
                .map_err(|error| DatagramSendError::Transport(error.to_string()))?;
        }
        Ok(())
    }

    async fn establish(
        connection: quinn::Connection,
        local: SessionIdentity,
        role: SessionRole,
    ) -> Result<Self, SessionError> {
        validate_alpn(&connection)?;
        let (mut send, recv) = connection.open_bi().await?;
        let mut reader = ControlReader::new(recv);
        // Both peers send their two handshake records immediately. Keep the
        // pair in one QUIC write: this makes the initial control batch
        // indivisible across implementations with different send schedulers.
        let ready = v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(v1::control_envelope::Body::SessionReady(v1::SessionReady {
                protocol_version: Some(v1::ProtocolVersion {
                    major: u32::from(PROTOCOL_MAJOR),
                    minor: u32::from(PROTOCOL_MINOR),
                }),
            })),
        };
        write_records(&mut send, &[(&local.hello(), true), (&ready, false)]).await?;
        let peer_hello = reader.read_record().await?;
        let peer = peer_from_hello(peer_hello)?;
        let ready = reader.read_record().await?;
        validate_session_ready(ready)?;
        let next_capability_id = match role {
            SessionRole::Initiator => 1,
        };
        Ok(Self(Arc::new(SessionInner {
            connection,
            datagram_send: std::sync::Mutex::new(()),
            datagram_routes: std::sync::Mutex::new(FxHashMap::default()),
            datagram_dispatch_started: std::sync::atomic::AtomicBool::new(false),
            control_send: Mutex::new(send),
            control_recv: Mutex::new(reader),
            event_wait: Mutex::new(()),
            queued_events: Mutex::new(VecDeque::new()),
            capabilities: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1),
            next_capability_id: AtomicU64::new(next_capability_id),
            next_flow_id: AtomicU64::new(next_capability_id),
            peer,
            local_endpoints: local.endpoints,
        })))
    }

    async fn establish_responder(
        connection: quinn::Connection,
        local: SessionIdentity,
        mut send: quinn::SendStream,
        mut reader: ControlReader,
        first: v1::ControlEnvelope,
    ) -> Result<Self, SessionError> {
        let peer = peer_from_hello(first)?;
        let ready = v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(v1::control_envelope::Body::SessionReady(v1::SessionReady {
                protocol_version: Some(v1::ProtocolVersion {
                    major: u32::from(PROTOCOL_MAJOR),
                    minor: u32::from(PROTOCOL_MINOR),
                }),
            })),
        };
        write_records(&mut send, &[(&local.hello(), true), (&ready, false)]).await?;
        let ready = reader.read_record().await?;
        validate_session_ready(ready)?;
        Ok(Self(Arc::new(SessionInner {
            connection,
            datagram_send: std::sync::Mutex::new(()),
            datagram_routes: std::sync::Mutex::new(FxHashMap::default()),
            datagram_dispatch_started: std::sync::atomic::AtomicBool::new(false),
            control_send: Mutex::new(send),
            control_recv: Mutex::new(reader),
            event_wait: Mutex::new(()),
            queued_events: Mutex::new(VecDeque::new()),
            capabilities: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1),
            next_capability_id: AtomicU64::new(2),
            next_flow_id: AtomicU64::new(2),
            peer,
            local_endpoints: local.endpoints,
        })))
    }

    async fn send(&self, body: v1::control_envelope::Body) -> Result<(), SessionError> {
        self.send_envelope(v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(body),
        })
        .await
    }

    async fn send_with_request(
        &self,
        request_id: u64,
        body: v1::control_envelope::Body,
    ) -> Result<(), SessionError> {
        self.send_envelope(v1::ControlEnvelope {
            request_id,
            response_to: 0,
            body: Some(body),
        })
        .await
    }

    async fn send_response(
        &self,
        response_to: u64,
        body: v1::control_envelope::Body,
    ) -> Result<(), SessionError> {
        self.send_envelope(v1::ControlEnvelope {
            request_id: 0,
            response_to,
            body: Some(body),
        })
        .await
    }

    async fn send_envelope(&self, envelope: v1::ControlEnvelope) -> Result<(), SessionError> {
        // encode_record applies the envelope invariants; validating here too
        // would double the check on every control send.
        let mut send = self.0.control_send.lock().await;
        write_record(&mut send, &envelope, false).await
    }

    fn allocate_request_id(&self) -> u64 {
        allocate_nonzero(&self.0.next_request_id)
    }
    fn allocate_capability_id(&self) -> u64 {
        allocate_nonzero(&self.0.next_capability_id)
    }

    fn allocate_flow_id(&self) -> u64 {
        allocate_nonzero(&self.0.next_flow_id)
    }
}

fn peer_certificate_der(connection: &quinn::Connection) -> Option<Vec<u8>> {
    connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certificates| {
            certificates
                .first()
                .map(|certificate| certificate.as_ref().to_vec())
        })
}

fn validate_alpn(connection: &quinn::Connection) -> Result<(), SessionError> {
    if connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .as_deref()
        != Some(ALPN)
    {
        return Err(SessionError::UnexpectedRecord("QUIC ALPN is not anchor/1"));
    }
    Ok(())
}

fn allocate_nonzero(counter: &AtomicU64) -> u64 {
    loop {
        let value = counter.fetch_add(1, Ordering::Relaxed);
        if value != 0 {
            return value;
        }
    }
}

async fn write_record(
    send: &mut quinn::SendStream,
    envelope: &v1::ControlEnvelope,
    first: bool,
) -> Result<(), SessionError> {
    let mut frame = Vec::new();
    encode_record_into(envelope, first, &mut frame)?;
    send.write_all(&frame).await?;
    send.flush().await?;
    Ok(())
}

async fn write_records(
    send: &mut quinn::SendStream,
    records: &[(&v1::ControlEnvelope, bool)],
) -> Result<(), SessionError> {
    let mut frame = Vec::new();
    for (envelope, first) in records {
        encode_record_into(envelope, *first, &mut frame)?;
    }
    send.write_all(&frame).await?;
    send.flush().await?;
    Ok(())
}

/// Encode one control record directly into `frame`. Prost's
/// `encode_length_delimited` emits the same LEB128 length prefix as
/// `encode_varint`, so this avoids the intermediate `encode_to_vec`
/// allocation and payload memcpy the old two-step path needed.
fn encode_record_into(
    envelope: &v1::ControlEnvelope,
    first: bool,
    frame: &mut Vec<u8>,
) -> Result<(), SessionError> {
    validate_control_envelope(envelope)?;
    if envelope.encoded_len() > MAX_CONTROL_RECORD_BYTES {
        return Err(ProtocolViolation::ControlRecordTooLarge.into());
    }
    frame.reserve(envelope.encoded_len() + 16);
    if first {
        frame.extend_from_slice(&CONTROL_MAGIC);
        frame.push(PROTOCOL_MAJOR);
        frame.push(PROTOCOL_MINOR);
    }
    envelope
        .encode_length_delimited(frame)
        .map_err(|_| ProtocolViolation::MalformedControlRecord)?;
    Ok(())
}

/// Read connection-scoped QUIC datagrams and fan them out to per-flow
/// channels by the ANFR flow ID. Datagrams for unregistered or closed flows
/// are dropped; a full flow queue drops too — the receiver treats that as
/// ordinary media loss and recovers from the next keyframe.
async fn dispatch_datagrams(session: Session) {
    // Media flows deliver thousands of consecutive datagrams to one flow ID;
    // remember the last route so the common case skips the map lock, the hash
    // probe, and the per-datagram `Sender` refcount churn.
    let mut cached_route: Option<(u64, tokio::sync::mpsc::Sender<Bytes>)> = None;
    loop {
        let Ok(datagram) = session.0.connection.read_datagram().await else {
            // Connection ended; dropping the session closes every channel.
            return;
        };
        let Some(flow_id) = crate::video_frame::datagram_flow_id(&datagram) else {
            continue;
        };
        if !matches!(&cached_route, Some((id, _)) if *id == flow_id) {
            cached_route = session
                .0
                .datagram_routes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&flow_id)
                .cloned()
                .map(|sender| (flow_id, sender));
        }
        let Some((_, sender)) = &cached_route else {
            continue;
        };
        if let Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) = sender.try_send(datagram) {
            session
                .0
                .datagram_routes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&flow_id);
            cached_route = None;
        }
    }
}

struct ControlReader {
    recv: quinn::RecvStream,
    first: bool,
}

impl ControlReader {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { recv, first: true }
    }

    async fn read_record(&mut self) -> Result<v1::ControlEnvelope, SessionError> {
        if self.first {
            let mut prefix = [0_u8; FIRST_RECORD_HEADER_BYTES];
            read_control_exact(&mut self.recv, &mut prefix).await?;
            if prefix[..CONTROL_MAGIC.len()] != CONTROL_MAGIC {
                return Err(ProtocolViolation::InvalidControlMagic.into());
            }
            // Major must match exactly. A peer's minor may be behind or equal
            // to ours (minor changes are additive by policy); a peer ahead of
            // us may rely on control-layer behavior we don't understand yet.
            if prefix[CONTROL_MAGIC.len()] != PROTOCOL_MAJOR
                || prefix[CONTROL_MAGIC.len() + 1] > PROTOCOL_MINOR
            {
                return Err(ProtocolViolation::UnsupportedControlVersion {
                    major: prefix[CONTROL_MAGIC.len()],
                    minor: prefix[CONTROL_MAGIC.len() + 1],
                }
                .into());
            }
            self.first = false;
        }
        let length = read_varint(&mut self.recv).await?;
        let length =
            usize::try_from(length).map_err(|_| ProtocolViolation::ControlRecordTooLarge)?;
        if length > MAX_CONTROL_RECORD_BYTES {
            return Err(ProtocolViolation::ControlRecordTooLarge.into());
        }
        let mut payload = vec![0_u8; length];
        read_control_exact(&mut self.recv, &mut payload).await?;
        let envelope = v1::ControlEnvelope::decode(payload.as_slice())
            .map_err(|_| ProtocolViolation::MalformedControlRecord)?;
        validate_control_envelope(&envelope)?;
        Ok(envelope)
    }
}

async fn read_control_exact(
    recv: &mut quinn::RecvStream,
    bytes: &mut [u8],
) -> Result<(), SessionError> {
    match recv.read_exact(bytes).await {
        Err(quinn::ReadExactError::FinishedEarly(_)) => Err(SessionError::ControlStreamEnded),
        Err(error) => Err(SessionError::ReadExact(error)),
        Ok(()) => Ok(()),
    }
}

async fn read_varint(recv: &mut quinn::RecvStream) -> Result<u64, SessionError> {
    let mut value = 0_u64;
    for index in 0..10 {
        let byte = match recv.read_u8().await {
            Ok(byte) => byte,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(SessionError::ControlStreamEnded);
            }
            Err(error) => return Err(SessionError::Io(error)),
        };
        if index == 9 && byte > 1 {
            return Err(ProtocolViolation::ControlRecordTooLarge.into());
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ProtocolViolation::ControlRecordTooLarge.into())
}

fn peer_from_hello(envelope: v1::ControlEnvelope) -> Result<SessionPeer, SessionError> {
    let Some(v1::control_envelope::Body::SessionHello(hello)) = envelope.body else {
        return Err(SessionError::UnexpectedRecord("expected SessionHello"));
    };
    let version = hello
        .protocol_version
        .ok_or(SessionError::UnexpectedRecord(
            "SessionHello missing version",
        ))?;
    if version.major != u32::from(PROTOCOL_MAJOR) || version.minor > u32::from(PROTOCOL_MINOR) {
        return Err(ProtocolViolation::UnsupportedControlVersion {
            major: version.major as u8,
            minor: version.minor as u8,
        }
        .into());
    }
    let node_id = hello.node_id.ok_or(SessionError::UnexpectedRecord(
        "SessionHello missing node ID",
    ))?;
    let node_id_bytes = node_id.value;
    let node_id_length = node_id_bytes.len();
    let node_id = node_id_bytes
        .try_into()
        .map_err(|_| ProtocolViolation::InvalidLength {
            field: "node_id",
            expected: NODE_ID_BYTES,
            actual: node_id_length,
        })?;
    let display = hello.display.ok_or(SessionError::UnexpectedRecord(
        "SessionHello missing display",
    ))?;
    Ok(SessionPeer {
        node_id,
        display_name: display.display_name,
        device_kind: display.device_kind,
        endpoints: hello.endpoints,
    })
}

fn validate_session_ready(envelope: v1::ControlEnvelope) -> Result<(), SessionError> {
    let Some(v1::control_envelope::Body::SessionReady(ready)) = envelope.body else {
        return Err(SessionError::UnexpectedRecord("expected SessionReady"));
    };
    let version = ready
        .protocol_version
        .ok_or(SessionError::UnexpectedRecord(
            "SessionReady missing version",
        ))?;
    if version.major != u32::from(PROTOCOL_MAJOR) || version.minor > u32::from(PROTOCOL_MINOR) {
        return Err(ProtocolViolation::UnsupportedControlVersion {
            major: version.major as u8,
            minor: version.minor as u8,
        }
        .into());
    }
    Ok(())
}

fn decode_event(envelope: v1::ControlEnvelope) -> Result<SessionEvent, SessionError> {
    let response_to = envelope.response_to;
    match envelope.body.ok_or(ProtocolViolation::MissingBody)? {
        v1::control_envelope::Body::CapabilityOpen(message) => {
            Ok(SessionEvent::CapabilityOpenRequested {
                request_id: envelope.request_id,
                capability_session_id: message.capability_session_id,
                endpoint_id: message.endpoint_id,
                capability_name: message.capability_name,
                capability_major: message.capability_major,
            })
        }
        v1::control_envelope::Body::CapabilityOpened(message) => {
            Ok(SessionEvent::CapabilityOpened {
                response_to,
                capability_session_id: message.capability_session_id,
            })
        }
        v1::control_envelope::Body::CapabilityClose(message) => {
            Ok(SessionEvent::CapabilityClosed {
                capability_session_id: message.capability_session_id,
                reason: message.reason,
            })
        }
        v1::control_envelope::Body::CapabilityRecord(message) => {
            Ok(SessionEvent::CapabilityRecord {
                capability_session_id: message.capability_session_id,
                type_url: message.type_url,
                payload: message.payload,
            })
        }
        v1::control_envelope::Body::StreamOpen(message) => Ok(SessionEvent::StreamOpenRequested {
            request_id: envelope.request_id,
            quic_stream_id: message.quic_stream_id,
            capability_session_id: message.capability_session_id,
            payload_type_url: message.payload_type_url,
        }),
        v1::control_envelope::Body::StreamOpened(message) => Ok(SessionEvent::StreamOpened {
            response_to,
            quic_stream_id: message.quic_stream_id,
        }),
        v1::control_envelope::Body::StreamClose(message) => Ok(SessionEvent::StreamClosed {
            quic_stream_id: message.quic_stream_id,
        }),
        v1::control_envelope::Body::DatagramFlowOpen(message) => {
            Ok(SessionEvent::DatagramFlowOpenRequested {
                request_id: envelope.request_id,
                capability_session_id: message.capability_session_id,
                flow_id: message.flow_id,
                payload_type_url: message.payload_type_url,
            })
        }
        v1::control_envelope::Body::DatagramFlowOpened(message) => {
            Ok(SessionEvent::DatagramFlowOpened {
                response_to,
                flow_id: message.flow_id,
            })
        }
        v1::control_envelope::Body::DatagramFlowClose(message) => {
            Ok(SessionEvent::DatagramFlowClosed {
                flow_id: message.flow_id,
            })
        }
        v1::control_envelope::Body::Ping(message) => Ok(SessionEvent::Ping {
            nonce: message.nonce,
        }),
        v1::control_envelope::Body::Pong(message) => Ok(SessionEvent::Pong {
            nonce: message.nonce,
        }),
        v1::control_envelope::Body::ProtocolError(message) => Ok(SessionEvent::ProtocolError {
            response_to,
            code: message.code,
            message: message.message,
        }),
        v1::control_envelope::Body::SessionClose(message) => Ok(SessionEvent::SessionClosed {
            reason: message.reason,
        }),
        _ => Err(SessionError::UnexpectedRecord(
            "session setup record after handshake",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_nonzero_and_skip_wraparound() {
        let counter = AtomicU64::new(u64::MAX);
        assert_eq!(allocate_nonzero(&counter), u64::MAX);
        assert_eq!(allocate_nonzero(&counter), 1);
    }

    #[test]
    fn capability_records_require_advertised_type_url() {
        let capability = v1::CapabilityAdvertisement {
            name: "org.anchor.clipboard".into(),
            major: 1,
            record_type_urls: vec!["type.googleapis.com/example.Clipboard".into()],
            supports_datagrams: false,
        };
        assert!(
            capability
                .record_type_urls
                .iter()
                .any(|url| url == "type.googleapis.com/example.Clipboard")
        );
    }
}
