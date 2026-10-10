use crate::impl_enum_discriminant;

/// `OpenRGB` protocol packet ID.
///
/// See [Open SDK documentation](https://gitlab.com/CalcProgrammer1/OpenRGB/-/wikis/OpenRGB-SDK-Documentation#packet-ids) for more information.
#[derive(PartialEq, Debug, Copy, Clone)]
pub(crate) enum PacketId {
    /// Request `RGBController` device count from server.
    RequestControllerCount = 0,

    /// Request `RGBController` data block.
    RequestControllerData = 1,

    /// Request `OpenRGB` SDK protocol version from server.
    RequestProtocolVersion = 40,

    /// Send client name string to server.
    SetClientName = 50,

    /// Indicate to clients that device list has updated.
    DeviceListUpdated = 100,

    /// Request a device rescan. (Protocol 5)
    RequestDeviceRescan = 140,

    /// Request profile list. (Protocol 2)
    RequestProfileList = 150,

    /// Save current configuration in a new profile. (Protocol 2)
    RequestSaveProfile = 151,

    /// Load a given profile. (Protocol 2)
    RequestLoadProfile = 152,

    /// Delete a given profile. (Protocol 2)
    RequestDeleteProfile = 153,

    /// Request list of plugins. (Protocol 4)
    RequestPluginList = 200,

    /// Plugin specific request. (Protocol 4)
    PluginSpecific = 201,

    /// `RGBController::ResizeZone()`.
    RGBControllerResizeZone = 1000,

    /// `RGBController::ClearSegments()`. (Protocol 5)
    RgbControllerClearSegments = 1001,

    /// `RGBController::AddSegment()`. (Protocol 5)
    RGBControllerAddSegment = 1002,

    /// `RGBController::UpdateLEDs()`.
    RGBControllerUpdateLeds = 1050,

    /// `RGBController::UpdateZoneLEDs()`.
    RGBControllerUpdateZoneLeds = 1051,

    /// `RGBController::UpdateSingleLED()`.
    RGBControllerUpdateSingleLed = 1052,

    /// `RGBController::SetCustomMode()`.
    RGBControllerSetCustomMode = 1100,

    /// `RGBController::UpdateMode()`.
    RGBControllerUpdateMode = 1101,

    /// `RGBController::SaveMode()`. (Protocol 3)
    RGBControllerSaveMode = 1102,
}

impl_enum_discriminant!(
    PacketId,
    RequestControllerCount: 0,
    RequestControllerData: 1,
    RequestProtocolVersion: 40,
    SetClientName: 50,
    DeviceListUpdated: 100,
    RequestDeviceRescan: 140,
    RequestProfileList: 150,
    RequestSaveProfile: 151,
    RequestLoadProfile: 152,
    RequestDeleteProfile: 153,
    RequestPluginList: 200,
    PluginSpecific: 201,
    RGBControllerResizeZone: 1000,
    RgbControllerClearSegments: 1001,
    RGBControllerAddSegment: 1002,
    RGBControllerUpdateLeds: 1050,
    RGBControllerUpdateZoneLeds: 1051,
    RGBControllerUpdateSingleLed: 1052,
    RGBControllerSetCustomMode: 1100,
    RGBControllerUpdateMode: 1101,
    RGBControllerSaveMode: 1102
);

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::{PacketId, WriteMessage};

    #[tokio::test]
    async fn test_read_001() -> Result<(), Box<dyn Error>> {
        let mut buf = WriteMessage::new(crate::DEFAULT_PROTOCOL);
        let mut msg = buf.push_value(&152_u32)?.to_received_msg();

        assert_eq!(msg.read_value::<PacketId>()?, PacketId::RequestLoadProfile);
        Ok(())
    }

    #[tokio::test]
    async fn test_write_001() -> Result<(), Box<dyn Error>> {
        let mut buf = WriteMessage::new(crate::DEFAULT_PROTOCOL);
        let mut msg = buf
            .push_value(&PacketId::RequestLoadProfile)?
            .to_received_msg();
        assert_eq!(msg.read_value::<u32>()?, 152);
        Ok(())
    }
}
