import AppKit
import Foundation
import NetSentryCore
import NetSentryIPC
import NetSentryDetection
import NetSentryPersistence
import UserNotifications
import os

/// Process-level lifecycle for the collector LaunchAgent (an LSUIElement app so AppKit notifications
/// and user notifications work). launchd keeps it alive; SIGTERM triggers a graceful drain.
final class CollectorApp: NSObject, NSApplicationDelegate, @unchecked Sendable {
    static let shared = CollectorApp()
    private let log = Log.logger("main", process: "collector")
    private var service: CollectorService!
    private var xpc: XPCServer!
    private var observers: SystemObservers?
    private var lockFD: Int32 = -1
    private var shuttingDown = false
    private var healthPushTask: Task<Void, Never>?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.prohibited)
        guard acquireSingleInstanceLock() else {
            log.error("Another collector instance is running; exiting")
            exit(0)
        }
        let config = BootstrapConfig.loadOrCreate()
        service = CollectorService(configuration: config)
        xpc = XPCServer(service: service)
        xpc.start()
        let notifier = AlertNotifier()
        let broadcaster = xpc!
        Task { await service.setOnAlert { alert, isNew in
            let posted = isNew && config.notificationsEnabled && notifier.post(alert)
            broadcaster.broadcast(AlertRaised(id: alert.id, title: alert.title, summary: alert.summary, severity: alert.severity, isNew: isNew, clientID: alert.clientID, notified: posted))
        } }
        observers = SystemObservers(health: service.health)
        installSignalHandlers()
        Task {
            await service.start()
            self.healthPushTask = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(2))
                    guard let self else { return }
                    let snap = await self.service.snapshot()
                    self.xpc.broadcast(HealthChanged(snapshot: snap))
                }
            }
        }
        log.notice("\(Branding.productName, privacy: .public) collector \(Branding.version, privacy: .public) (\(Branding.build, privacy: .public)) launched")
    }

    func requestShutdown(reason: String) async {
        guard !shuttingDown else { return }
        shuttingDown = true
        log.notice("Shutdown requested: \(reason, privacy: .public)")
        healthPushTask?.cancel()
        await service.stop()
        await MainActor.run { NSApp.terminate(nil) }
    }

    private func installSignalHandlers() {
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { Task { await CollectorApp.shared.requestShutdown(reason: "signal \(sig)") } }
            src.resume()
            signalSources.append(src)
        }
    }
    private var signalSources: [any DispatchSourceSignal] = []

    private func acquireSingleInstanceLock() -> Bool {
        let dir = StorageLocations.sharedSupportDirectory()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let path = dir.appending(path: "collector.lock").path
        lockFD = open(path, O_CREAT | O_RDWR, 0o600)
        guard lockFD >= 0 else { return true }
        return flock(lockFD, LOCK_EX | LOCK_NB) == 0
    }
}

let app = NSApplication.shared
app.delegate = CollectorApp.shared
app.run()


/// Native notifications for new alerts; tapping opens the dashboard at the alert (netsentry://alert/<id>).
final class AlertNotifier: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    private let log = Log.logger("notify", process: "collector")
    private let center = UNUserNotificationCenter.current()
    private var authorized = false

    override init() {
        super.init()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] ok, error in
            self?.authorized = ok
            if let error { self?.log.error("notification authorization: \(error.localizedDescription, privacy: .public)") }
        }
        let open = UNNotificationAction(identifier: "open", title: "Open in \(Branding.productName)", options: [.foreground])
        center.setNotificationCategories([UNNotificationCategory(identifier: "alert", actions: [open], intentIdentifiers: [], options: [])])
    }

    /// Returns false when this process may not post (an ad-hoc signed dev agent, or the user declined); the dashboard
    /// then posts on the collector's behalf while it is running.
    @discardableResult
    func post(_ alert: Alert) -> Bool {
        guard authorized, alert.severity >= .low else { return false }
        let content = UNMutableNotificationContent()
        content.title = alert.title
        content.body = alert.summary
        content.categoryIdentifier = "alert"
        content.userInfo = ["alertID": alert.id]
        content.sound = alert.severity >= .high ? .default : nil
        content.interruptionLevel = alert.severity >= .high ? .timeSensitive : .active
        center.add(UNNotificationRequest(identifier: "alert-\(alert.id)", content: content, trigger: nil)) { [weak self] error in
            if let error { self?.log.error("notification failed: \(error.localizedDescription, privacy: .public)") }
        }
        return true
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        if let id = response.notification.request.content.userInfo["alertID"] as? Int64, let url = URL(string: "\(Branding.urlScheme)://alert/\(id)") {
            NSWorkspace.shared.open(url)
        }
        completionHandler()
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}
