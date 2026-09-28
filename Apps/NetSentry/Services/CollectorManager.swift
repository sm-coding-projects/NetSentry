import Foundation
import NetSentryCore
import Security
import ServiceManagement
import os

/// Registers the bundled LaunchAgent with launchd through SMAppService (login item integration).
@MainActor
final class CollectorManager {
    private let log = Log.logger("sm", process: "app")
    private let service = SMAppService.agent(plistName: Branding.launchAgentPlistName)

    /// Last known status; refreshed off the main thread because `SMAppService.status` is an XPC call
    /// to smd that can stall while launchd is in a bad state.
    private(set) var cachedStatus: SMAppService.Status = .notRegistered
    private var refreshing = false

    var status: SMAppService.Status { cachedStatus }

    func refreshStatus() {
        guard !refreshing else { return }
        refreshing = true
        let plist = Branding.launchAgentPlistName
        Task.detached(priority: .utility) { [weak self] in
            let s = SMAppService.agent(plistName: plist).status
            await MainActor.run { self?.cachedStatus = s; self?.refreshing = false }
        }
    }

    var statusDescription: String {
        switch status {
        case .notRegistered: "Not registered"
        case .enabled: "Enabled"
        case .requiresApproval: "Requires approval in System Settings › Login Items"
        case .notFound: "Agent not found in app bundle"
        @unknown default: "Unknown"
        }
    }

    func register() throws {
        try service.register()
        cachedStatus = service.status
        if let fp = Self.collectorFingerprint() { UserDefaults.standard.set(fp, forKey: Self.fingerprintKey) }
        log.notice("LaunchAgent registered; status \(String(describing: self.service.status), privacy: .public)")
    }

    func unregister() async throws {
        try await service.unregister()
        cachedStatus = service.status
        log.notice("LaunchAgent unregistered")
    }

    /// Completion-handler variant for contexts without a running run loop (developer CLI flag).
    nonisolated func unregister(completion: @escaping @Sendable ((any Error)?) -> Void) {
        SMAppService.agent(plistName: Branding.launchAgentPlistName).unregister(completionHandler: completion)
    }

    /// launchd pins a registration to the collector's exact cdhash when the build is ad-hoc signed, so after
    /// an app update the stale registration refuses to spawn the new binary (exit 78, EX_CONFIG).
    /// Re-registers once whenever the bundled collector differs from the one last registered.
    func reregisterIfCollectorChanged() async {
        guard let current = Self.collectorFingerprint(),
              UserDefaults.standard.string(forKey: Self.fingerprintKey) != current else { return }
        let plist = Branding.launchAgentPlistName
        let status = await Task.detached(priority: .utility) { SMAppService.agent(plistName: plist).status }.value
        guard status == .enabled else { return }   // not registered yet: the wizard/settings toggle registers it
        log.notice("Bundled collector changed; re-registering LaunchAgent")
        do {
            try? await service.unregister()
            try register()
        } catch {
            log.error("Re-registering LaunchAgent failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    private static let fingerprintKey = "registeredCollectorCDHash"

    /// Hex cdhash of the collector bundled inside this app.
    private static func collectorFingerprint() -> String? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/NetSentryCollector.app")
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess,
              let hash = (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data else { return nil }
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    func openLoginItemsSettings() { SMAppService.openSystemSettingsLoginItems() }
}
