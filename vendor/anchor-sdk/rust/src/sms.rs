//! Typed records for `org.anchor.sms@1`.
use crate::v1::{self, CapabilityAdvertisement, EndpointAdvertisement};
use prost::Message;
pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.sms";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const MESSAGE_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.sms.SmsMessage";
pub const SEND_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.sms.SmsSend";
pub const SEND_RESULT_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.sms.SmsSendResult";
pub const CONVERSATION_REQUEST_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.sms.ConversationRequest";
pub const CONVERSATION_LIST_REQUEST_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.sms.ConversationListRequest";
pub const CONVERSATION_SNAPSHOT_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.sms.ConversationSnapshot";
pub const CONVERSATION_LIST_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.sms.ConversationList";
pub const ATTACHMENT_REQUEST_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.sms.AttachmentRequest";
pub fn advertisement() -> CapabilityAdvertisement {
    CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![
            MESSAGE_TYPE_URL.into(),
            SEND_TYPE_URL.into(),
            SEND_RESULT_TYPE_URL.into(),
            CONVERSATION_REQUEST_TYPE_URL.into(),
            CONVERSATION_LIST_REQUEST_TYPE_URL.into(),
            CONVERSATION_SNAPSHOT_TYPE_URL.into(),
            CONVERSATION_LIST_TYPE_URL.into(),
            ATTACHMENT_REQUEST_TYPE_URL.into(),
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
pub type SmsMessage = v1::capabilities::sms::SmsMessage;
pub type SmsSend = v1::capabilities::sms::SmsSend;
pub type SmsSendResult = v1::capabilities::sms::SmsSendResult;
pub type ConversationMessage = v1::capabilities::sms::ConversationMessage;
pub type ConversationRequest = v1::capabilities::sms::ConversationRequest;
pub type ConversationListRequest = v1::capabilities::sms::ConversationListRequest;
pub type AttachmentRequest = v1::capabilities::sms::AttachmentRequest;
pub type ConversationSnapshot = v1::capabilities::sms::ConversationSnapshot;
pub type ConversationList = v1::capabilities::sms::ConversationList;
pub fn decode_message(b: &[u8]) -> Result<SmsMessage, prost::DecodeError> {
    SmsMessage::decode(b)
}
pub fn decode_send(b: &[u8]) -> Result<SmsSend, prost::DecodeError> {
    SmsSend::decode(b)
}
pub fn encode_send(v: SmsSend) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn encode_conversation_request(v: ConversationRequest) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn encode_conversation_list_request(v: ConversationListRequest) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn encode_attachment_request(v: AttachmentRequest) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn decode_conversation_snapshot(b: &[u8]) -> Result<ConversationSnapshot, prost::DecodeError> {
    ConversationSnapshot::decode(b)
}
pub fn decode_conversation_list(b: &[u8]) -> Result<ConversationList, prost::DecodeError> {
    ConversationList::decode(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn send_round_trip() {
        let v = SmsSend {
            client_message_id: "c".into(),
            address: "+1".into(),
            body: "hi".into(),
        };
        assert_eq!(decode_send(&encode_send(v.clone())).unwrap(), v);
    }
}
