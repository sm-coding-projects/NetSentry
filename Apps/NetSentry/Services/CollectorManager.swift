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
    ///
    /// Called on launch (`running == nil`) and after every status poll with the collector's reported
    /// version/build (nil when unreachable). While the bundled collector has not been confirmed running, the
    /// agent is re-registered, at most every 15 s and 5 times per launch: the first attempt can race with
    /// macOS processing the updated app and leave the old constraint in place.
    func ensureBundledCollectorRunning(running: (version: String, build: String)?) async {
        guard let bundled = Self.collectorFingerprint() else { return }
        if let running, running.version == Branding.version, running.build == Branding.build {
            UserDefaults.standard.set(bundled, forKey: Self.fingerprintKey)   // confirmed: this build is running
            return
        }
        guard UserDefaults.standard.string(forKey: Self.fingerprintKey) != bundled || running != nil else { return }
        guard !reregistering, reregisterAttempts < 5, reregisterAttemptedAt.map({ Date.now.timeIntervalSince($0) > 15 }) ?? true else { return }
        reregistering = true
        defer { reregistering = false }
        let plist = Branding.launchAgentPlistName
        guard await Task.detached(priority: .utility, operation: { SMAppService.agent(plistName: plist).status }).value == .enabled else { return }
        reregisterAttempts += 1
        reregisterAttemptedAt = .now
        log.notice("Bundled collector not running yet (attempt \(self.reregisterAttempts)); re-registering LaunchAgent")
        do {
            try? await service.unregister()
            for _ in 0..<20 {   // let smd finish removing the job before submitting it again
                if await Task.detached(operation: { SMAppService.agent(plistName: plist).status }).value == .notRegistered { break }
                try? await Task.sleep(for: .milliseconds(250))
            }
            try register()
        } catch {
            log.error("Re-registering LaunchAgent failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    private var reregistering = false
    private var reregisterAttempts = 0
    private var reregisterAttemptedAt: Date?
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
