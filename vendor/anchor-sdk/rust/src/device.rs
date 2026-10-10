//! Wire helpers for the `org.anchor.device@1` capability.

use crate::v1::{self, CapabilityAdvertisement, EndpointAdvertisement};
use prost::Message;

pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.device";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const STATE_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.device.DeviceState";

pub fn advertisement() -> CapabilityAdvertisement {
    CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![STATE_TYPE_URL.into()],
        supports_datagrams: false,
    }
}

pub fn endpoint_advertisement() -> EndpointAdvertisement {
    EndpointAdvertisement {
        endpoint_id: ENDPOINT_ID.into(),
        capabilities: vec![advertisement()],
    }
}

pub type DeviceState = v1::capabilities::device::DeviceState;

pub fn encode_state(state: DeviceState) -> Vec<u8> {
    state.encode_to_vec()
}

pub fn decode_state(bytes: &[u8]) -> Result<DeviceState, prost::DecodeError> {
    DeviceState::decode(bytes)
}
