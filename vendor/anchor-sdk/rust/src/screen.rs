//! Wire helpers for screen control records.
use crate::v1::{self, CapabilityAdvertisement, EndpointAdvertisement};
use prost::Message;
pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.screen";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const START_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.screen.ScreenStart";
pub const STOP_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.screen.ScreenStop";
pub const SELECT_OUTPUT_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.screen.ScreenSelectOutput";
pub const REQUEST_KEYFRAME_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.screen.ScreenRequestKeyframe";
pub const OUTPUT_LIST_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.screen.ScreenOutputList";
pub const STATUS_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.screen.ScreenStatus";
/// The protobuf type URL used to identify the fixed-header datagram payload.
pub const FRAME_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.screen.ScreenFrame";
pub fn advertisement() -> CapabilityAdvertisement {
    CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![
            START_TYPE_URL.into(),
            STOP_TYPE_URL.into(),
            SELECT_OUTPUT_TYPE_URL.into(),
            REQUEST_KEYFRAME_TYPE_URL.into(),
            OUTPUT_LIST_TYPE_URL.into(),
            STATUS_TYPE_URL.into(),
            FRAME_TYPE_URL.into(),
        ],
        // Screen video rides lossy datagrams: parity rebuilds singly-lost
        // fragments, and skipping head-of-line blocking saves ~1 RTT per
        // dropped packet. Reference-chain integrity on this path is enforced
        // by mark_frame_gap (any dropped/coalesced AU suppresses P-frames
        // until an IDR). ANCHOR_SCREEN_DATAGRAMS=0 forces the reliable stream
        // as a debug escape hatch.
        supports_datagrams: std::env::var("ANCHOR_SCREEN_DATAGRAMS")
            .map_or(true, |value| value != "0"),
    }
}
pub fn endpoint_advertisement() -> EndpointAdvertisement {
    EndpointAdvertisement {
        endpoint_id: ENDPOINT_ID.into(),
        capabilities: vec![advertisement()],
    }
}
pub type ScreenOutput = v1::capabilities::screen::ScreenOutput;
pub type ScreenOutputList = v1::capabilities::screen::ScreenOutputList;
pub type ScreenStatus = v1::capabilities::screen::ScreenStatus;

pub fn encode_output_list(outputs: Vec<ScreenOutput>) -> Vec<u8> {
    ScreenOutputList { outputs }.encode_to_vec()
}

pub fn encode_status(status: ScreenStatus) -> Vec<u8> {
    status.encode_to_vec()
}

pub fn decode_start(b: &[u8]) -> Result<v1::capabilities::screen::ScreenStart, prost::DecodeError> {
    v1::capabilities::screen::ScreenStart::decode(b)
}
pub fn decode_select_output(
    b: &[u8],
) -> Result<v1::capabilities::screen::ScreenSelectOutput, prost::DecodeError> {
    v1::capabilities::screen::ScreenSelectOutput::decode(b)
}
pub fn decode_stop(b: &[u8]) -> Result<v1::capabilities::screen::ScreenStop, prost::DecodeError> {
    v1::capabilities::screen::ScreenStop::decode(b)
}
pub fn decode_request_keyframe(
    b: &[u8],
) -> Result<v1::capabilities::screen::ScreenRequestKeyframe, prost::DecodeError> {
    v1::capabilities::screen::ScreenRequestKeyframe::decode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_advertises_the_frame_datagram_flow() {
        let advertisement = advertisement();
        assert!(advertisement.supports_datagrams);
        assert!(
            advertisement
                .record_type_urls
                .iter()
                .any(|url| url == FRAME_TYPE_URL)
        );
    }
}
