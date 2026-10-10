//! Typed records for `org.anchor.files@1`.
use crate::v1::{self, CapabilityAdvertisement, EndpointAdvertisement};
use prost::Message;

pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.files";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const OFFER_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.files.FileOffer";
pub const DECISION_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.files.FileDecision";
pub const CONTENT_START_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.files.FileContentStart";
/// Identifies the reliable byte stream carrying the offered file contents.
pub const CONTENT_STREAM_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.files.FileContent";
pub const COMPLETE_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.files.FileComplete";

pub fn advertisement() -> CapabilityAdvertisement {
    CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![
            OFFER_TYPE_URL.into(),
            DECISION_TYPE_URL.into(),
            CONTENT_START_TYPE_URL.into(),
            CONTENT_STREAM_TYPE_URL.into(),
            COMPLETE_TYPE_URL.into(),
        ],
        supports_datagrams: false,
    }
}
pub fn endpoint_advertisement() -> EndpointAdvertisement {
    EndpointAdvertisement {
        endpoint_id: ENDPOINT_ID.into(),
        capabilities: vec![advertisement()],
    }
}
pub type FileOffer = v1::capabilities::files::FileOffer;
pub type FileDecision = v1::capabilities::files::FileDecision;
pub type FileContentStart = v1::capabilities::files::FileContentStart;
pub type FileComplete = v1::capabilities::files::FileComplete;
pub fn encode_offer(v: FileOffer) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn decode_offer(b: &[u8]) -> Result<FileOffer, prost::DecodeError> {
    FileOffer::decode(b)
}
pub fn encode_decision(v: FileDecision) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn decode_decision(b: &[u8]) -> Result<FileDecision, prost::DecodeError> {
    FileDecision::decode(b)
}
pub fn decode_content_start(b: &[u8]) -> Result<FileContentStart, prost::DecodeError> {
    FileContentStart::decode(b)
}
pub fn encode_content_start(v: FileContentStart) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn decode_complete(b: &[u8]) -> Result<FileComplete, prost::DecodeError> {
    FileComplete::decode(b)
}
pub fn encode_complete(v: FileComplete) -> Vec<u8> {
    v.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offer_round_trip() {
        let offer = FileOffer {
            transfer_id: vec![7; 16],
            filename: "a.txt".into(),
            mime_type: "text/plain".into(),
            byte_length: 3,
            sha256: vec![1; 32],
        };
        assert_eq!(decode_offer(&encode_offer(offer.clone())).unwrap(), offer);
        assert_eq!(advertisement().record_type_urls.len(), 5);
    }

    #[test]
    fn decision_round_trip_preserves_transfer_and_policy() {
        let decision = FileDecision {
            transfer_id: vec![3; 16],
            accepted: false,
        };
        assert_eq!(
            decode_decision(&encode_decision(decision.clone())).unwrap(),
            decision
        );
    }
}
