//! Wire helpers for the `org.anchor.notifications@1` capability.

use prost::Message;

use crate::v1::{self, CapabilityAdvertisement, EndpointAdvertisement};

pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.notifications";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const POSTED_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.notifications.NotificationPosted";
pub const DISMISSED_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.notifications.NotificationDismissed";
pub const INVOKE_ACTION_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.notifications.NotificationInvokeAction";

pub fn advertisement() -> CapabilityAdvertisement {
    CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![
            POSTED_TYPE_URL.into(),
            DISMISSED_TYPE_URL.into(),
            INVOKE_ACTION_TYPE_URL.into(),
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

pub type NotificationPosted = v1::capabilities::notifications::NotificationPosted;
pub type NotificationDismissed = v1::capabilities::notifications::NotificationDismissed;
pub type NotificationInvokeAction = v1::capabilities::notifications::NotificationInvokeAction;

pub fn encode_posted(message: NotificationPosted) -> Vec<u8> {
    message.encode_to_vec()
}
pub fn decode_posted(bytes: &[u8]) -> Result<NotificationPosted, prost::DecodeError> {
    NotificationPosted::decode(bytes)
}
pub fn decode_dismissed(bytes: &[u8]) -> Result<NotificationDismissed, prost::DecodeError> {
    NotificationDismissed::decode(bytes)
}
pub fn decode_invoke_action(bytes: &[u8]) -> Result<NotificationInvokeAction, prost::DecodeError> {
    NotificationInvokeAction::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posted_round_trip_and_advertisement_are_canonical() {
        let message = NotificationPosted {
            notification_id: "n-1".into(),
            application_id: "org.example.app".into(),
            application_name: "Example".into(),
            title: "Hello".into(),
            body: "World".into(),
            posted_at_unix_ms: 42,
            actions: vec![],
        };
        let decoded = decode_posted(&encode_posted(message.clone())).unwrap();
        assert_eq!(decoded, message);
        assert!(
            advertisement()
                .record_type_urls
                .contains(&POSTED_TYPE_URL.into())
        );
    }
}
