import Foundation
import NetSentryCore
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

    func openLoginItemsSettings() { SMAppService.openSystemSettingsLoginItems() }
}
