//! Quinn transport controls for the Rust/Linux SDK.
//!
//! This module configures only Anchor's QUIC invariants. Identity creation,
//! certificate pinning, reconnect policy, and host permissions stay outside the
//! transport library so they can have matching Kotlin and Swift semantics.

use std::{sync::Arc, time::Duration};

use quinn::{ClientConfig, ServerConfig};
use thiserror::Error;

use crate::ALPN;

/// Quinn datagram send queue capacity. Sized to admit the largest legal
/// access unit; `Session` applies the smaller stale-queue bound on top.
pub(crate) const DATAGRAM_SEND_BUFFER_BYTES: usize = 10 * 1024 * 1024;

/// Bind a QUIC UDP socket with enlarged kernel buffers. Media datagram
/// bursts (multi-MiB IDR keyframes at 60fps) can overrun the ~200 KiB Linux
/// default and drop packets before Quinn ever sees them; the kernel clamps
/// to rmem_max/wmem_max, so asking for 8 MiB is safe. Applies to outbound
/// endpoints too — a client that only ever *receives* a large screen frame
/// bursts just as hard on its recv buffer.
pub fn bind_udp_socket(address: std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    const SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;
    // Best-effort: a kernel that rejects the size still serves the default.
    let _ = socket.set_recv_buffer_size(SOCKET_BUFFER_BYTES);
    let _ = socket.set_send_buffer_size(SOCKET_BUFFER_BYTES);
    // DSCP EF (TOS 0xB8): most APs map EF into the WMM voice/video queue, so
    // media datagrams bypass bulk-transfer queueing under load. Same reason
    // FaceTime/Sidecar mark their streams — costs nothing, matters on a
    // congested AP.
    const DSCP_EF_TOS: u32 = 0xB8;
    let _ = socket.set_tos_v4(DSCP_EF_TOS);
    let _ = socket.set_tclass_v6(DSCP_EF_TOS);
    if address.is_ipv6() {
        // Match quinn::Endpoint::server: an IPv6 bind stays dual-stack so an
        // IPv4 phone on the same LAN can still reach it.
        let _ = socket.set_only_v6(false);
    }
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[derive(Debug, Error)]
pub enum QuinnConfigError {
    #[error("TLS configuration is not QUIC/TLS-1.3 compatible: {0}")]
    Tls(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

/// Converts a caller-owned TLS client configuration into an Anchor QUIC client
/// configuration. The caller must configure its paired-peer certificate pin
/// verifier before invoking this function.
pub fn client_config(mut tls: rustls::ClientConfig) -> Result<ClientConfig, QuinnConfigError> {
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut config = ClientConfig::new(Arc::new(quic_tls));
    config.transport_config(transport_config());
    Ok(config)
}

/// Converts a caller-owned TLS server configuration into an Anchor QUIC server
/// configuration. A production caller must require/validate its peer identity
/// according to the currently approved pairing security model.
pub fn server_config(mut tls: rustls::ServerConfig) -> Result<ServerConfig, QuinnConfigError> {
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = ServerConfig::with_crypto(Arc::new(quic_tls));
    config.transport_config(transport_config());
    Ok(config)
}

/// Keep an otherwise idle SDK session alive. Clipboard and control sessions
/// can legitimately have no application data for minutes; Quinn's default
/// idle timeout is short enough to tear those sessions down unexpectedly.
/// Both sides use the same policy so the MsQuic and Quinn adapters behave the
/// same way on the wire.
fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    // Physical room for the largest legal access unit (~8.7MiB once a
    // MAX_FRAME_BYTES frame is split into datagrams plus per-item overhead);
    // Quinn accounts queued bytes rather than preallocating, so the size costs
    // nothing while idle. Staleness is bounded at the admission layer instead
    // (Session caps the *backlog*, not the capacity): a smaller buffer here
    // would make any frame above ~245KiB categorically unsendable even on an
    // idle connection — a keyframe that large can never be recovered.
    config.datagram_send_buffer_size(DATAGRAM_SEND_BUFFER_BYTES);
    // Anchor sessions run on LAN/Wi-Fi peer-to-peer paths; the 333ms spec
    // default initial RTT delays the congestion controller's ramp-up right
    // after connect, when the first keyframe burst matters most.
    config.initial_rtt(Duration::from_millis(50));
    // Absorb decode/render jitter bursts without dropping media datagrams;
    // consumers drain promptly, so a larger buffer only raises the ceiling.
    config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    // Quinn sizes stream flow control for 12.5MB/s at a 100ms RTT
    // (1.25MiB/stream). High-bitrate screen sessions on Wi-Fi can exceed
    // that, stalling the reliable stream on window updates. 8MiB keeps the
    // window above bandwidth-delay product for realistic bursts.
    config.stream_receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024));
    // Match Quinn's default 8x ratio between connection send budget and the
    // per-stream receive window so a burst is never artificially capped.
    config.send_window(64 * 1024 * 1024);
    // Experimental: `ANCHOR_QUIC_CC=bbr` swaps Cubic for BBR, which models
    // bottleneck bandwidth instead of backing off on loss — better suited to
    // lossy Wi-Fi media sessions. Default stays Cubic until measured.
    if std::env::var_os("ANCHOR_QUIC_CC").is_some_and(|v| v == "bbr") {
        config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    config.keep_alive_interval(Some(Duration::from_secs(10)));
    config.max_idle_timeout(Some(
        Duration::from_secs(120)
            .try_into()
            .expect("120 seconds is a valid QUIC idle timeout"),
    ));
    Arc::new(config)
}
