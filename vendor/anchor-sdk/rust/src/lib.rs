//! Native Rust SDK foundation for Anchor Protocol v1.
//!
//! This crate deliberately owns protocol validation and state-independent wire
//! helpers first. QUIC, discovery, and host storage adapters build on this
//! stable boundary rather than making networking policy part of protobuf types.

use prost::Message;
use sha2::Digest;
use thiserror::Error;

pub mod additional;
pub mod camera;
pub mod clipboard;
pub mod commands;
pub mod device;
pub mod files;
pub mod input;
pub mod listener;
pub mod media;
pub mod notifications;
pub mod pairing;
pub mod quinn_transport;
pub mod screen;
pub mod session;
pub mod sms;
pub mod video_frame;

pub use listener::{
    AnchorListener, IncomingConnection, ListenerConfig, ListenerError, ListenerIdentity,
};
pub use session::{
    AcceptedSession, Capability, DatagramFlow, DatagramSendError, DatagramTransportStats,
    PairingSession, ReliableRecvStream, ReliableSendStream, ReliableStream, Session, SessionError,
    SessionEvent, SessionIdentity, SessionPeer,
};

pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

/// Generated Protocol v1 message types. The SDK's public helpers use these
/// exact types, so Rust callers cannot accidentally model a divergent wire
/// contract.
pub use wire::anchor::v1;

pub const ALPN: &[u8] = b"anchor/1";
pub const CONTROL_MAGIC: [u8; 4] = *b"ANCR";
pub const PROTOCOL_MAJOR: u8 = 1;
pub const PROTOCOL_MINOR: u8 = 0;
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NODE_ID_BYTES: usize = 32;
pub const INVITATION_ID_BYTES: usize = 16;
pub const SHA256_BYTES: usize = 32;
pub const MAX_CONTROL_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProtocolViolation {
    #[error("unsupported protocol major {0}")]
    UnsupportedMajor(u32),
    #[error("unsupported protocol minor {0}: ahead of this build's supported minor")]
    UnsupportedMinor(u32),
    #[error("pairing invitation has an invalid {field} length: expected {expected}, got {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("pairing invitation endpoint is empty")]
    EmptyEndpoint,
    #[error("pairing invitation device id is empty")]
    EmptyDeviceId,
    #[error("pairing invitation has expired")]
    InvitationExpired,
    #[error("pairing invitation certificate does not match its advertised fingerprint")]
    CertificateFingerprintMismatch,
    #[error("control envelope cannot set request_id and response_to together")]
    AmbiguousCorrelation,
    #[error("control envelope has no body")]
    MissingBody,
    #[error("control stream is missing the ANCR preface")]
    InvalidControlMagic,
    #[error("unsupported control-stream version {major}.{minor}")]
    UnsupportedControlVersion { major: u8, minor: u8 },
    #[error("control record exceeds the {MAX_CONTROL_RECORD_BYTES}-byte limit")]
    ControlRecordTooLarge,
    #[error("control stream ended before a complete record was available")]
    TruncatedControlRecord,
    #[error("control record protobuf is malformed")]
    MalformedControlRecord,
}

/// Validates a QR/manual invitation before a QUIC connection is attempted.
/// Certificate-pin verification remains the transport's responsibility.
pub fn validate_pairing_invitation(
    invitation: &v1::PairingInvitation,
    now_unix_ms: u64,
) -> Result<(), ProtocolViolation> {
    let version = invitation
        .protocol_version
        .as_ref()
        .ok_or(ProtocolViolation::UnsupportedMajor(0))?;
    if version.major != u32::from(PROTOCOL_MAJOR) {
        return Err(ProtocolViolation::UnsupportedMajor(version.major));
    }
    // A minor ahead of ours may rely on control-layer behavior we don't
    // understand yet; a minor behind or equal to ours is always safe.
    if version.minor > u32::from(PROTOCOL_MINOR) {
        return Err(ProtocolViolation::UnsupportedMinor(version.minor));
    }
    validate_length(
        "invitation_id",
        &invitation.invitation_id,
        INVITATION_ID_BYTES,
    )?;
    if invitation.endpoint.trim().is_empty() {
        return Err(ProtocolViolation::EmptyEndpoint);
    }
    if invitation.inviter_device_id.trim().is_empty() {
        return Err(ProtocolViolation::EmptyDeviceId);
    }
    let node_id = invitation
        .inviter_node_id
        .as_ref()
        .ok_or(ProtocolViolation::InvalidLength {
            field: "inviter_node_id",
            expected: NODE_ID_BYTES,
            actual: 0,
        })?;
    validate_length("inviter_node_id", &node_id.value, NODE_ID_BYTES)?;
    validate_length(
        "inviter_certificate_fingerprint",
        &invitation.inviter_certificate_fingerprint,
        SHA256_BYTES,
    )?;
    if invitation.inviter_certificate_der.is_empty()
        || invitation.inviter_certificate_der.len() > 4096
    {
        return Err(ProtocolViolation::InvalidLength {
            field: "inviter_certificate_der",
            expected: 4096,
            actual: invitation.inviter_certificate_der.len(),
        });
    }
    let actual_fingerprint = sha2::Sha256::digest(&invitation.inviter_certificate_der);
    if actual_fingerprint.as_slice() != invitation.inviter_certificate_fingerprint {
        return Err(ProtocolViolation::CertificateFingerprintMismatch);
    }
    validate_length("pairing_nonce", &invitation.pairing_nonce, SHA256_BYTES)?;
    if invitation.expires_at_unix_ms <= now_unix_ms {
        return Err(ProtocolViolation::InvitationExpired);
    }
    Ok(())
}

/// Applies common invariants before phase and capability-specific dispatch.
pub fn validate_control_envelope(envelope: &v1::ControlEnvelope) -> Result<(), ProtocolViolation> {
    if envelope.request_id != 0 && envelope.response_to != 0 {
        return Err(ProtocolViolation::AmbiguousCorrelation);
    }
    if envelope.body.is_none() {
        return Err(ProtocolViolation::MissingBody);
    }
    Ok(())
}

/// Encodes the v1 stream preface and one protobuf envelope.
pub fn encode_first_control_record(
    envelope: &v1::ControlEnvelope,
) -> Result<Vec<u8>, ProtocolViolation> {
    validate_control_envelope(envelope)?;
    let payload_len = envelope.encoded_len();
    if payload_len > MAX_CONTROL_RECORD_BYTES {
        return Err(ProtocolViolation::ControlRecordTooLarge);
    }
    let mut frame = Vec::with_capacity(CONTROL_MAGIC.len() + 2 + 10 + payload_len);
    frame.extend_from_slice(&CONTROL_MAGIC);
    frame.push(PROTOCOL_MAJOR);
    frame.push(PROTOCOL_MINOR);
    // encode_length_delimited writes the same LEB128 length prefix as
    // encode_varint followed by the payload, without a separate encode_to_vec
    // allocation and copy.
    envelope
        .encode_length_delimited(&mut frame)
        .map_err(|_| ProtocolViolation::MalformedControlRecord)?;
    Ok(frame)
}

/// Decodes the first control-stream record and returns the envelope plus the
/// number of consumed bytes. Callers retain any following records for their
/// stream accumulator. Limits are applied before protobuf allocation.
pub fn decode_first_control_record(
    input: &[u8],
) -> Result<(v1::ControlEnvelope, usize), ProtocolViolation> {
    if input.len() < CONTROL_MAGIC.len() + 2 {
        return Err(ProtocolViolation::TruncatedControlRecord);
    }
    if input[..CONTROL_MAGIC.len()] != CONTROL_MAGIC {
        return Err(ProtocolViolation::InvalidControlMagic);
    }
    let major = input[CONTROL_MAGIC.len()];
    let minor = input[CONTROL_MAGIC.len() + 1];
    // Major must match exactly; a peer's minor may be behind or equal to
    // ours, since minor changes are additive by policy (see VERSIONING.md).
    if major != PROTOCOL_MAJOR || minor > PROTOCOL_MINOR {
        return Err(ProtocolViolation::UnsupportedControlVersion { major, minor });
    }
    let (length, length_bytes) = decode_varint(&input[CONTROL_MAGIC.len() + 2..])?;
    let length = usize::try_from(length).map_err(|_| ProtocolViolation::ControlRecordTooLarge)?;
    if length > MAX_CONTROL_RECORD_BYTES {
        return Err(ProtocolViolation::ControlRecordTooLarge);
    }
    let payload_start = CONTROL_MAGIC.len() + 2 + length_bytes;
    let payload_end = payload_start
        .checked_add(length)
        .ok_or(ProtocolViolation::ControlRecordTooLarge)?;
    let payload = input
        .get(payload_start..payload_end)
        .ok_or(ProtocolViolation::TruncatedControlRecord)?;
    let envelope = v1::ControlEnvelope::decode(payload)
        .map_err(|_| ProtocolViolation::MalformedControlRecord)?;
    validate_control_envelope(&envelope)?;
    Ok((envelope, payload_end))
}

fn validate_length(
    field: &'static str,
    value: &[u8],
    expected: usize,
) -> Result<(), ProtocolViolation> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(ProtocolViolation::InvalidLength {
            field,
            expected,
            actual: value.len(),
        })
    }
}

fn decode_varint(input: &[u8]) -> Result<(u64, usize), ProtocolViolation> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().copied().enumerate() {
        if index == 10 || (index == 9 && byte > 1) {
            return Err(ProtocolViolation::ControlRecordTooLarge);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(ProtocolViolation::TruncatedControlRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use v1::control_envelope::Body;

    fn reference_varint(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        while value >= 0x80 {
            bytes.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
        bytes
    }

    #[test]
    fn pairing_reject_matches_control_fixture() {
        let envelope = v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(Body::PairingReject(v1::PairingReject {})),
        };
        assert_eq!(
            hex::encode(encode_first_control_record(&envelope).unwrap()),
            "414e43520100026200"
        );
        assert_eq!(
            decode_first_control_record(&encode_first_control_record(&envelope).unwrap())
                .unwrap()
                .0,
            envelope
        );
    }

    #[test]
    fn reviewed_control_fixtures_decode_as_complete_records() {
        for fixture in [
            include_str!("../../protocol/fixtures/v1/control/capability-open.hex"),
            include_str!("../../protocol/fixtures/v1/control/stream-open.hex"),
            include_str!("../../protocol/fixtures/v1/control/datagram-flow-open.hex"),
            include_str!("../../protocol/fixtures/v1/control/ping.hex"),
            include_str!("../../protocol/fixtures/v1/control/pong.hex"),
            include_str!("../../protocol/fixtures/v1/control/capability-opened.hex"),
            include_str!("../../protocol/fixtures/v1/control/stream-opened.hex"),
            include_str!("../../protocol/fixtures/v1/control/datagram-flow-opened.hex"),
            include_str!("../../protocol/fixtures/v1/control/session-close.hex"),
        ] {
            let bytes = hex::decode(fixture.trim()).unwrap();
            let (_, consumed) = decode_first_control_record(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
        }
    }

    #[test]
    fn correlation_cannot_be_both_request_and_response() {
        let envelope = v1::ControlEnvelope {
            request_id: 1,
            response_to: 2,
            body: Some(Body::PairingReject(v1::PairingReject {})),
        };
        assert_eq!(
            validate_control_envelope(&envelope),
            Err(ProtocolViolation::AmbiguousCorrelation)
        );
    }

    #[test]
    fn invitation_must_have_exact_security_identifiers() {
        let certificate = vec![5; 128];
        let invitation = v1::PairingInvitation {
            protocol_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
            invitation_id: vec![1; INVITATION_ID_BYTES],
            endpoint: "192.0.2.5:4242".into(),
            inviter_device_id: "desktop-1".into(),
            inviter_node_id: Some(v1::NodeId {
                value: vec![2; NODE_ID_BYTES],
            }),
            inviter_certificate_fingerprint: sha2::Sha256::digest(&certificate).to_vec(),
            expires_at_unix_ms: 101,
            pairing_nonce: vec![4; SHA256_BYTES],
            inviter_certificate_der: certificate,
        };
        assert_eq!(validate_pairing_invitation(&invitation, 100), Ok(()));
    }

    #[test]
    fn invitation_rejects_a_certificate_that_does_not_match_its_pin() {
        let invitation = v1::PairingInvitation {
            protocol_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
            invitation_id: vec![1; INVITATION_ID_BYTES],
            endpoint: "192.0.2.5:5027".into(),
            inviter_device_id: "desktop-1".into(),
            inviter_node_id: Some(v1::NodeId {
                value: vec![2; NODE_ID_BYTES],
            }),
            inviter_certificate_fingerprint: vec![3; SHA256_BYTES],
            expires_at_unix_ms: 101,
            pairing_nonce: vec![4; SHA256_BYTES],
            inviter_certificate_der: vec![5; 128],
        };
        assert_eq!(
            validate_pairing_invitation(&invitation, 100),
            Err(ProtocolViolation::CertificateFingerprintMismatch)
        );
    }

    #[test]
    fn pairing_persists_the_transport_verified_pin_only_after_approval() {
        struct Store(Option<pairing::PairedPeer>);
        impl pairing::PairedPeerStore for Store {
            type Error = ();
            fn save(&mut self, peer: &pairing::PairedPeer) -> Result<(), Self::Error> {
                self.0 = Some(peer.clone());
                Ok(())
            }
        }

        let mut controller = pairing::PairingController::default();
        let hello = v1::PairingHello {
            invitation_id: vec![],
            node_id: Some(v1::NodeId {
                value: vec![9; NODE_ID_BYTES],
            }),
            display: Some(v1::PeerDisplayInfo {
                display_name: "Phone".into(),
                device_kind: 2,
            }),
            transcript_hash: vec![7; SHA256_BYTES],
        };
        controller.receive_hello(&hello, [4; SHA256_BYTES]).unwrap();
        let mut store = Store(None);
        let approve = controller.approve(&mut store).unwrap();
        assert_eq!(approve.transcript_hash, vec![7; SHA256_BYTES]);
        assert_eq!(store.0.unwrap().certificate_fingerprint, [4; SHA256_BYTES]);
    }

    #[test]
    fn control_decoder_accepts_a_peer_minor_at_or_below_ours_and_rejects_ahead() {
        let envelope = v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(Body::PairingReject(v1::PairingReject {})),
        };
        let mut frame = encode_first_control_record(&envelope).unwrap();
        // Byte layout: ANCR(4) + major(1) + minor(1) + varint length + payload.
        assert_eq!(frame[CONTROL_MAGIC.len() + 1], PROTOCOL_MINOR);
        // A peer on our own minor (the only value representable while
        // PROTOCOL_MINOR is 0) must still decode successfully.
        assert!(decode_first_control_record(&frame).is_ok());
        // A peer on a newer minor must be rejected, since it may rely on
        // control-layer behavior we don't understand yet.
        frame[CONTROL_MAGIC.len() + 1] = PROTOCOL_MINOR + 1;
        assert_eq!(
            decode_first_control_record(&frame),
            Err(ProtocolViolation::UnsupportedControlVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR + 1,
            })
        );
    }

    #[test]
    fn pairing_invitation_rejects_a_minor_ahead_of_ours() {
        let certificate = vec![5; 128];
        let invitation = v1::PairingInvitation {
            protocol_version: Some(v1::ProtocolVersion {
                major: 1,
                minor: u32::from(PROTOCOL_MINOR) + 1,
            }),
            invitation_id: vec![1; INVITATION_ID_BYTES],
            endpoint: "192.0.2.5:4242".into(),
            inviter_device_id: "desktop-1".into(),
            inviter_node_id: Some(v1::NodeId {
                value: vec![2; NODE_ID_BYTES],
            }),
            inviter_certificate_fingerprint: sha2::Sha256::digest(&certificate).to_vec(),
            expires_at_unix_ms: 101,
            pairing_nonce: vec![4; SHA256_BYTES],
            inviter_certificate_der: certificate,
        };
        assert_eq!(
            validate_pairing_invitation(&invitation, 100),
            Err(ProtocolViolation::UnsupportedMinor(
                u32::from(PROTOCOL_MINOR) + 1
            ))
        );
    }

    #[test]
    fn control_decoder_rejects_invalid_preface_and_truncation() {
        assert_eq!(
            decode_first_control_record(b"nope"),
            Err(ProtocolViolation::TruncatedControlRecord)
        );
        assert_eq!(
            decode_first_control_record(b"NOPE\x01\x00\x00"),
            Err(ProtocolViolation::InvalidControlMagic)
        );
        assert_eq!(
            decode_first_control_record(b"ANCR\x01\x00\x80"),
            Err(ProtocolViolation::TruncatedControlRecord)
        );
    }

    #[test]
    fn control_decoder_rejects_an_oversized_declared_length_before_reading_payload() {
        let mut frame = Vec::from(CONTROL_MAGIC);
        frame.extend_from_slice(&[PROTOCOL_MAJOR, PROTOCOL_MINOR]);
        frame.extend_from_slice(&reference_varint((MAX_CONTROL_RECORD_BYTES + 1) as u64));

        assert_eq!(
            decode_first_control_record(&frame),
            Err(ProtocolViolation::ControlRecordTooLarge),
        );
    }

    #[test]
    fn control_decoder_reports_only_the_first_record_length_with_a_trailing_record() {
        let first = v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(Body::Ping(v1::Ping {
                nonce: 0x0102_0304_0506_0708,
            })),
        };
        let second = v1::ControlEnvelope {
            request_id: 0,
            response_to: 0,
            body: Some(Body::Pong(v1::Pong {
                nonce: 0x1112_1314_1516_1718,
            })),
        };
        let first_record = encode_first_control_record(&first).unwrap();
        let mut stream = first_record.clone();
        stream.extend_from_slice(&encode_first_control_record(&second).unwrap());

        let (decoded, consumed) = decode_first_control_record(&stream).unwrap();
        assert_eq!(decoded, first);
        assert_eq!(consumed, first_record.len());
    }

    #[test]
    fn every_public_capability_advertises_a_nonempty_unique_record_allow_list() {
        let advertisements = [
            camera::advertisement(),
            clipboard::advertisement(),
            commands::advertisement(),
            device::advertisement(),
            files::advertisement(),
            input::advertisement(),
            media::advertisement(),
            notifications::advertisement(),
            screen::advertisement(),
            sms::advertisement(),
        ];

        for advertisement in advertisements {
            assert!(!advertisement.name.is_empty());
            assert_ne!(advertisement.major, 0);
            assert!(!advertisement.record_type_urls.is_empty());
            for type_url in &advertisement.record_type_urls {
                assert!(!type_url.is_empty());
                assert_eq!(
                    advertisement
                        .record_type_urls
                        .iter()
                        .filter(|candidate| *candidate == type_url)
                        .count(),
                    1,
                    "{} advertises {type_url} more than once",
                    advertisement.name,
                );
            }
        }
    }

    proptest! {
        #[test]
        fn control_varint_decoder_matches_an_independent_reference(value in any::<u64>()) {
            let bytes = reference_varint(value);
            let (decoded, consumed) = decode_varint(&bytes).unwrap();
            prop_assert_eq!(decoded, value);
            prop_assert_eq!(consumed, bytes.len());
        }

        #[test]
        fn control_decoder_reports_truncation_at_every_boundary_of_a_valid_record(
            nonce in any::<u64>(),
        ) {
            let envelope = v1::ControlEnvelope {
                request_id: 0,
                response_to: 0,
                body: Some(Body::Ping(v1::Ping { nonce })),
            };
            let record = encode_first_control_record(&envelope).unwrap();
            for length in 0..record.len() {
                prop_assert!(
                    matches!(
                        decode_first_control_record(&record[..length]),
                        Err(ProtocolViolation::TruncatedControlRecord)
                    ),
                    "truncation at byte {length} was not reported as a truncated control record",
                );
            }
        }
    }
}
