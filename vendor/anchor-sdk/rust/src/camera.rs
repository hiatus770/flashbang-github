//! Typed camera control/status records; encoded frames use the negotiated datagram flow.
use crate::v1::{self, CapabilityAdvertisement, EndpointAdvertisement};
use prost::Message;
pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.camera";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const START_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.camera.CameraStart";
pub const STOP_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.camera.CameraStop";
pub const STATUS_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.camera.CameraStatus";
pub const CODEC_CONFIG_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.camera.CameraCodecConfig";
pub const KEYFRAME_NEEDED_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.camera.CameraKeyframeNeeded";
pub const CONTROL_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.camera.CameraControl";
/// The protobuf type URL used to identify the fixed-header datagram payload.
pub const FRAME_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.camera.CameraFrame";
pub fn advertisement() -> CapabilityAdvertisement {
    CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![
            START_TYPE_URL.into(),
            STOP_TYPE_URL.into(),
            STATUS_TYPE_URL.into(),
            CODEC_CONFIG_TYPE_URL.into(),
            KEYFRAME_NEEDED_TYPE_URL.into(),
            CONTROL_TYPE_URL.into(),
            FRAME_TYPE_URL.into(),
        ],
        supports_datagrams: true,
    }
}
pub fn endpoint_advertisement() -> EndpointAdvertisement {
    EndpointAdvertisement {
        endpoint_id: ENDPOINT_ID.into(),
        capabilities: vec![advertisement()],
    }
}
pub fn decode_start(b: &[u8]) -> Result<v1::capabilities::camera::CameraStart, prost::DecodeError> {
    v1::capabilities::camera::CameraStart::decode(b)
}
pub fn decode_stop(b: &[u8]) -> Result<v1::capabilities::camera::CameraStop, prost::DecodeError> {
    v1::capabilities::camera::CameraStop::decode(b)
}
pub fn decode_status(
    b: &[u8],
) -> Result<v1::capabilities::camera::CameraStatus, prost::DecodeError> {
    v1::capabilities::camera::CameraStatus::decode(b)
}
pub fn decode_control(
    b: &[u8],
) -> Result<v1::capabilities::camera::CameraControl, prost::DecodeError> {
    v1::capabilities::camera::CameraControl::decode(b)
}

pub type CameraControl = v1::capabilities::camera::CameraControl;

pub fn encode_control(control: CameraControl) -> Vec<u8> {
    control.encode_to_vec()
}
