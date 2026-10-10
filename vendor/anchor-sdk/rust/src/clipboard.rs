//! Canonical helpers for the `org.anchor.clipboard@1` capability.
//!
//! Clipboard providers exchange serialized `ClipboardPublish` and
//! `ClipboardClear` messages through the negotiated capability record path.
//! Keeping the type URL and protobuf construction here prevents each host
//! application from inventing a subtly different payload contract.

use prost::Message;

use crate::{NODE_ID_BYTES, v1};

pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.clipboard";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const PUBLISH_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.clipboard.ClipboardPublish";
pub const CLEAR_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.clipboard.ClipboardClear";

pub fn advertisement() -> v1::CapabilityAdvertisement {
    v1::CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![PUBLISH_TYPE_URL.into(), CLEAR_TYPE_URL.into()],
        supports_datagrams: false,
    }
}

pub fn endpoint_advertisement() -> v1::EndpointAdvertisement {
    v1::EndpointAdvertisement {
        endpoint_id: ENDPOINT_ID.into(),
        capabilities: vec![advertisement()],
    }
}

pub type ClipboardPublish = v1::capabilities::clipboard::ClipboardPublish;
pub type ClipboardClear = v1::capabilities::clipboard::ClipboardClear;

pub fn encode_text(
    origin_node_id: [u8; NODE_ID_BYTES],
    revision: u64,
    text: impl Into<String>,
) -> Vec<u8> {
    ClipboardPublish {
        origin_node_id: Some(v1::NodeId {
            value: origin_node_id.to_vec(),
        }),
        revision,
        content: Some(
            v1::capabilities::clipboard::clipboard_publish::Content::TextUtf8(text.into()),
        ),
    }
    .encode_to_vec()
}

pub fn encode_png(
    origin_node_id: [u8; NODE_ID_BYTES],
    revision: u64,
    png: impl Into<Vec<u8>>,
) -> Vec<u8> {
    ClipboardPublish {
        origin_node_id: Some(v1::NodeId {
            value: origin_node_id.to_vec(),
        }),
        revision,
        content: Some(v1::capabilities::clipboard::clipboard_publish::Content::Png(png.into())),
    }
    .encode_to_vec()
}

pub fn decode_publish(bytes: &[u8]) -> Result<ClipboardPublish, prost::DecodeError> {
    ClipboardPublish::decode(bytes)
}

pub fn encode_clear(origin_node_id: [u8; NODE_ID_BYTES], revision: u64) -> Vec<u8> {
    ClipboardClear {
        origin_node_id: Some(v1::NodeId {
            value: origin_node_id.to_vec(),
        }),
        revision,
    }
    .encode_to_vec()
}

pub fn decode_clear(bytes: &[u8]) -> Result<ClipboardClear, prost::DecodeError> {
    ClipboardClear::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip_uses_canonical_type() {
        let bytes = encode_text([7; NODE_ID_BYTES], 4, "hello");
        let message = decode_publish(&bytes).unwrap();
        assert_eq!(message.revision, 4);
        assert_eq!(
            message.origin_node_id.unwrap().value,
            vec![7; NODE_ID_BYTES]
        );
        assert!(matches!(
            message.content,
            Some(v1::capabilities::clipboard::clipboard_publish::Content::TextUtf8(text))
                if text == "hello"
        ));
    }

    #[test]
    fn clear_round_trip_preserves_revision() {
        let bytes = encode_clear([9; NODE_ID_BYTES], 8);
        let message = decode_clear(&bytes).unwrap();
        assert_eq!(message.revision, 8);
        assert_eq!(
            message.origin_node_id.unwrap().value,
            vec![9; NODE_ID_BYTES]
        );
    }
}
