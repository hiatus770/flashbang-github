//! Wire helpers for the `org.anchor.media@1` capability.

use crate::v1::{self, CapabilityAdvertisement, EndpointAdvertisement};
use prost::Message;

pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.media";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const STATE_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.media.MediaState";
pub const COMMAND_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.media.MediaCommand";
pub const MAX_ARTWORK_JPEG_BYTES: usize = 256 * 1024;

pub fn advertisement() -> CapabilityAdvertisement {
    CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![STATE_TYPE_URL.into(), COMMAND_TYPE_URL.into()],
        supports_datagrams: false,
    }
}
pub fn endpoint_advertisement() -> EndpointAdvertisement {
    EndpointAdvertisement {
        endpoint_id: ENDPOINT_ID.into(),
        capabilities: vec![advertisement()],
    }
}
pub type MediaState = v1::capabilities::media::MediaState;
pub type MediaCommand = v1::capabilities::media::MediaCommand;

pub fn encode_state(state: MediaState) -> Vec<u8> {
    state.encode_to_vec()
}
pub fn decode_state(bytes: &[u8]) -> Result<MediaState, prost::DecodeError> {
    MediaState::decode(bytes)
}
pub fn encode_command(command: MediaCommand) -> Vec<u8> {
    command.encode_to_vec()
}
pub fn decode_command(bytes: &[u8]) -> Result<MediaCommand, prost::DecodeError> {
    MediaCommand::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn advertisement_has_state_and_command_records() {
        let urls = advertisement().record_type_urls;
        assert!(urls.contains(&STATE_TYPE_URL.into()));
        assert!(urls.contains(&COMMAND_TYPE_URL.into()));
    }
}
