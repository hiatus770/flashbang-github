//! Typed records for `org.anchor.commands@1`.
use crate::v1::{self, CapabilityAdvertisement, EndpointAdvertisement};
use prost::Message;
pub const ENDPOINT_ID: &str = "io.anchor.desktop";
pub const CAPABILITY_NAME: &str = "org.anchor.commands";
pub const CAPABILITY_MAJOR: u32 = 1;
pub const RUN_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.commands.CommandRun";
pub const LIST_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.commands.CommandList";
pub const KILL_TYPE_URL: &str = "type.googleapis.com/anchor.v1.capabilities.commands.CommandKill";
pub const RESULT_TYPE_URL: &str =
    "type.googleapis.com/anchor.v1.capabilities.commands.CommandResult";
pub fn advertisement() -> CapabilityAdvertisement {
    CapabilityAdvertisement {
        name: CAPABILITY_NAME.into(),
        major: CAPABILITY_MAJOR,
        record_type_urls: vec![
            RUN_TYPE_URL.into(),
            RESULT_TYPE_URL.into(),
            LIST_TYPE_URL.into(),
            KILL_TYPE_URL.into(),
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
pub type CommandRun = v1::capabilities::commands::CommandRun;
pub type CommandResult = v1::capabilities::commands::CommandResult;
pub type CommandDefinition = v1::capabilities::commands::CommandDefinition;
pub type CommandList = v1::capabilities::commands::CommandList;
pub type CommandKill = v1::capabilities::commands::CommandKill;
pub fn decode_run(b: &[u8]) -> Result<CommandRun, prost::DecodeError> {
    CommandRun::decode(b)
}
pub fn decode_result(b: &[u8]) -> Result<CommandResult, prost::DecodeError> {
    CommandResult::decode(b)
}
pub fn encode_result(v: CommandResult) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn encode_list(v: CommandList) -> Vec<u8> {
    v.encode_to_vec()
}
pub fn decode_kill(b: &[u8]) -> Result<CommandKill, prost::DecodeError> {
    CommandKill::decode(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_round_trip() {
        let v = CommandRun {
            command_id: "open".into(),
            arguments: vec!["x".into()],
        };
        assert_eq!(decode_run(&v.encode_to_vec()).unwrap(), v);
    }

    #[test]
    fn result_round_trip_preserves_typed_correlation() {
        let v = CommandResult {
            command_id: "open".into(),
            execution_id: "exec-1".into(),
            status: "done".into(),
            exit_code: 0,
            error: String::new(),
            stdout: String::new(),
            stderr: String::new(),
        };
        assert_eq!(decode_result(&encode_result(v.clone())).unwrap(), v);
    }
}
