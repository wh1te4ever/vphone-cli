import Foundation
import Virtualization
import VPhoneObjC

/// Wrapper around the ObjC private API call to create a PV=3 hardware model.
///
/// The Virtualization.framework checks:
///   default_configuration_for_platform_version(3) validity byte =
///     (entitlements & 0x12) != 0
///   where bit 1 = com.apple.private.virtualization
///         bit 4 = com.apple.private.virtualization.security-research
///
/// Minimum host OS for PV=3: macOS 15.0 (Sequoia)
///
enum VPhoneHardware {
    /// Create a PV=3 VZMacHardwareModel. Throws if isSupported is false.
    static func createModel() throws -> VZMacHardwareModel {
        let model = VPhoneCreateHardwareModel()
        guard model.isSupported else {
            throw VPhoneError.hardwareModelNotSupported
        }
        return model
    }
}
