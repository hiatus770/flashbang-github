use crate::{NODE_ID_BYTES, ProtocolViolation, SHA256_BYTES, v1};

/// A peer that completed user-approved pairing and whose certificate is pinned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedPeer {
    pub node_id: [u8; NODE_ID_BYTES],
    pub certificate_fingerprint: [u8; SHA256_BYTES],
    pub display_name: String,
    pub device_kind: i32,
}

/// Host-owned persistence boundary. Desktop, Android, and iOS each adapt this
/// to their own secure store; the SDK never chooses a database or keychain.
pub trait PairedPeerStore {
    type Error;

    fn save(&mut self, peer: &PairedPeer) -> Result<(), Self::Error>;
}

/// A validated pairing hello from the initiating peer. The SDK checks
/// presence/length before any caller can observe this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub node_id: [u8; NODE_ID_BYTES],
    pub display_name: String,
    pub device_kind: i32,
    pub transcript_hash: [u8; SHA256_BYTES],
    pub invitation_id: Vec<u8>,
}

impl Hello {
    pub(crate) fn from_wire(hello: &v1::PairingHello) -> Result<Self, ProtocolViolation> {
        let node_id = hello
            .node_id
            .as_ref()
            .ok_or(ProtocolViolation::InvalidLength {
                field: "node_id",
                expected: NODE_ID_BYTES,
                actual: 0,
            })?;
        let display = hello
            .display
            .as_ref()
            .ok_or(ProtocolViolation::InvalidLength {
                field: "display",
                expected: 1,
                actual: 0,
            })?;
        let node_id_bytes: [u8; NODE_ID_BYTES] =
            node_id
                .value
                .as_slice()
                .try_into()
                .map_err(|_| ProtocolViolation::InvalidLength {
                    field: "node_id",
                    expected: NODE_ID_BYTES,
                    actual: node_id.value.len(),
                })?;
        let transcript_hash: [u8; SHA256_BYTES] =
            hello.transcript_hash.as_slice().try_into().map_err(|_| {
                ProtocolViolation::InvalidLength {
                    field: "transcript_hash",
                    expected: SHA256_BYTES,
                    actual: hello.transcript_hash.len(),
                }
            })?;
        Ok(Self {
            node_id: node_id_bytes,
            display_name: display.display_name.clone(),
            device_kind: display.device_kind,
            transcript_hash,
            invitation_id: hello.invitation_id.clone(),
        })
    }

    pub(crate) fn to_wire(&self) -> v1::PairingHello {
        v1::PairingHello {
            invitation_id: self.invitation_id.clone(),
            node_id: Some(v1::NodeId {
                value: self.node_id.to_vec(),
            }),
            display: Some(v1::PeerDisplayInfo {
                display_name: self.display_name.clone(),
                device_kind: self.device_kind,
            }),
            transcript_hash: self.transcript_hash.to_vec(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRequest {
    pub node_id: [u8; NODE_ID_BYTES],
    pub certificate_fingerprint: [u8; SHA256_BYTES],
    pub display_name: String,
    pub device_kind: i32,
    pub transcript_hash: [u8; SHA256_BYTES],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PairingState {
    #[default]
    Idle,
    AwaitingUser(PairingRequest),
    Paired(PairedPeer),
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingStateError {
    NotAwaitingUser,
    InvalidHello(ProtocolViolation),
    StoreFailed,
}

/// State owned by the host's one pairing UI flow. It has no sockets and never
/// persists a peer until `approve` succeeds.
#[derive(Debug, Default)]
pub struct PairingController {
    state: PairingState,
}

impl PairingController {
    pub fn state(&self) -> &PairingState {
        &self.state
    }

    /// Call after the transport has verified the pairing TLS certificate. The
    /// supplied fingerprint must be derived from that certificate, never from
    /// an asserted protobuf field.
    pub fn receive_hello(
        &mut self,
        hello: &v1::PairingHello,
        certificate_fingerprint: [u8; SHA256_BYTES],
    ) -> Result<(), PairingStateError> {
        let node_id = hello
            .node_id
            .as_ref()
            .ok_or_else(|| invalid_hello("node_id", 0, NODE_ID_BYTES))?;
        let display = hello
            .display
            .as_ref()
            .ok_or_else(|| invalid_hello("display", 0, 1))?;
        let request = PairingRequest {
            node_id: to_array("node_id", &node_id.value, NODE_ID_BYTES)?,
            certificate_fingerprint,
            display_name: display.display_name.clone(),
            device_kind: display.device_kind,
            transcript_hash: to_array("transcript_hash", &hello.transcript_hash, SHA256_BYTES)?,
        };
        self.state = PairingState::AwaitingUser(request);
        Ok(())
    }

    /// Saves the peer pin first, then returns the wire message the host sends
    /// over its existing pairing transport.
    pub fn approve<S: PairedPeerStore>(
        &mut self,
        store: &mut S,
    ) -> Result<v1::PairingApprove, PairingStateError> {
        let PairingState::AwaitingUser(request) = &self.state else {
            return Err(PairingStateError::NotAwaitingUser);
        };
        let peer = PairedPeer {
            node_id: request.node_id,
            certificate_fingerprint: request.certificate_fingerprint,
            display_name: request.display_name.clone(),
            device_kind: request.device_kind,
        };
        store
            .save(&peer)
            .map_err(|_| PairingStateError::StoreFailed)?;
        let approve = v1::PairingApprove {
            transcript_hash: request.transcript_hash.to_vec(),
            approver_certificate_der: Vec::new(),
            approver_device_id: String::new(),
        };
        self.state = PairingState::Paired(peer);
        Ok(approve)
    }

    pub fn reject(&mut self) -> Result<v1::PairingReject, PairingStateError> {
        if !matches!(self.state, PairingState::AwaitingUser(_)) {
            return Err(PairingStateError::NotAwaitingUser);
        }
        self.state = PairingState::Rejected;
        Ok(v1::PairingReject {})
    }
}

fn invalid_hello(field: &'static str, actual: usize, expected: usize) -> PairingStateError {
    PairingStateError::InvalidHello(ProtocolViolation::InvalidLength {
        field,
        expected,
        actual,
    })
}

fn to_array<const N: usize>(
    field: &'static str,
    value: &[u8],
    expected: usize,
) -> Result<[u8; N], PairingStateError> {
    value
        .try_into()
        .map_err(|_| invalid_hello(field, value.len(), expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn valid_hello() -> v1::PairingHello {
        v1::PairingHello {
            invitation_id: vec![1; 16],
            node_id: Some(v1::NodeId {
                value: vec![2; NODE_ID_BYTES],
            }),
            display: Some(v1::PeerDisplayInfo {
                display_name: "Phone".into(),
                device_kind: 2,
            }),
            transcript_hash: vec![3; SHA256_BYTES],
        }
    }

    struct StoreResult(Result<(), ()>);

    impl PairedPeerStore for StoreResult {
        type Error = ();

        fn save(&mut self, _: &PairedPeer) -> Result<(), Self::Error> {
            self.0
        }
    }

    #[test]
    fn failed_approval_keeps_the_request_awaiting_user_decision() {
        let mut controller = PairingController::default();
        controller
            .receive_hello(&valid_hello(), [4; SHA256_BYTES])
            .unwrap();
        let mut store = StoreResult(Err(()));

        assert_eq!(
            controller.approve(&mut store),
            Err(PairingStateError::StoreFailed)
        );
        assert!(matches!(controller.state(), PairingState::AwaitingUser(_)));
    }

    #[test]
    fn resolution_is_allowed_once_per_pairing_request() {
        let mut controller = PairingController::default();
        controller
            .receive_hello(&valid_hello(), [4; SHA256_BYTES])
            .unwrap();
        let mut store = StoreResult(Ok(()));

        assert!(controller.approve(&mut store).is_ok());
        assert_eq!(
            controller.approve(&mut store),
            Err(PairingStateError::NotAwaitingUser)
        );
        assert_eq!(controller.reject(), Err(PairingStateError::NotAwaitingUser));
    }

    proptest! {
        #[test]
        fn pairing_hello_rejects_every_noncanonical_node_id_length(
            length in prop::sample::select(vec![0_usize, 1, NODE_ID_BYTES - 1, NODE_ID_BYTES + 1, 64]),
        ) {
            let mut hello = valid_hello();
            hello.node_id = Some(v1::NodeId { value: vec![0; length] });
            let mut controller = PairingController::default();

            prop_assert_eq!(
                controller.receive_hello(&hello, [4; SHA256_BYTES]),
                Err(PairingStateError::InvalidHello(ProtocolViolation::InvalidLength {
                    field: "node_id",
                    expected: NODE_ID_BYTES,
                    actual: length,
                })),
            );
            prop_assert_eq!(controller.state(), &PairingState::Idle);
        }
    }
}
