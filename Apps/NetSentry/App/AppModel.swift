import AppKit
import Foundation
import NetSentryCore
import NetSentryIPC
import NetSentryPersistence
import NetSentryAnalytics
import NetSentryCorrelation
import Observation
import UserNotifications
import os

/// Root observable state for the dashboard: collector connection, latest health, and configuration draft.
@MainActor
@Observable
final class AppModel {
    let client = CollectorClient()
    let manager = CollectorManager()
    private let log = Log.logger("model", process: "app")

    var connectionState: CollectorClient.ConnectionState = .disconnected
    var health: HealthSnapshot?
    var configuration: CollectorConfiguration
    var lastError: String?
    var agentStatus: String = ""
    // Navigation state shared across views
    var requestedSection: Section?
    var investigationAnchor: InvestigationAnchor?
    var investigationTime: Timestamp?
    var pendingAlertID: Int64?
    var lastAlertEvent: AlertRaised?
    var openAlertCount = 0
    /// Shown once on first launch (configuration.setupCompleted is false) unless a developer flag is driving the app.
    var showSetupWizard = false
    private var wizardDecided = false
    // Live activity ring (bounded), fed by LiveBatch notifications.
    var liveRows: [LiveRow] = []
    var liveSampledOut = 0
    var livePaused = false
    var livePausedDropped = 0
    private var liveSubscription: UUID?
    private var liveSequence = 0
    static let liveRingSize = 2_000
    private var pollTask: Task<Void, Never>?
    private var notificationTask: Task<Void, Never>?

    init() {
        configuration = BootstrapConfig.loadOrCreate()
        client.onStateChange = { [weak self] s in Task { @MainActor in self?.connectionState = s } }
        manager.refreshStatus()
        agentStatus = manager.statusDescription
        startPolling()
        notificationTask = Task { [weak self] in
            guard let self else { return }
            for await env in self.client.notifications {
                switch env.kind {
                case HealthChanged.kind:
                    if let h = try? IPCCoding.decode(HealthChanged.self, from: env.payload) { self.health = h.snapshot }
                case LiveBatch.kind:
                    if let b = try? IPCCoding.decode(LiveBatch.self, from: env.payload) { self.ingestLive(b) }
                case AlertRaised.kind:
                    if let a = try? IPCCoding.decode(AlertRaised.self, from: env.payload) {
                        self.lastAlertEvent = a
                        if a.isNew { self.openAlertCount += 1; if !a.notified, self.configuration.notificationsEnabled { self.notifier.post(a) } }
                    }
                default: break
                }
            }
        }
    }

    private func startPolling() {
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(self?.connectionState == .connected ? 5 : 3))
            }
        }
    }

    func refresh() async {
        manager.refreshStatus()
        agentStatus = manager.statusDescription
        do {
            health = try await client.request(StatusRequest())
            configuration = try await client.request(ConfigGetRequest())
            lastError = nil
            decideWizard()
        } catch {
            if connectionState != .disconnected || health != nil { log.info("refresh failed: \(error.localizedDescription, privacy: .public)") }
            health = nil
        }
    }

    /// Applies configuration through the collector when it is reachable, otherwise saves the bootstrap file.
    func apply(_ config: CollectorConfiguration) async -> [String] {
        let errors = config.validate()
        guard errors.isEmpty else { return errors }
        configuration = config
        do {
            let reply = try await client.request(ConfigApplyRequest(configuration: config))
            if !reply.accepted { return reply.errors }
        } catch {
            do { try BootstrapConfig.save(config) } catch { return [error.localizedDescription] }
        }
        return []
    }

    let notifier = DashboardNotifier()

    /// The wizard appears when setup was never completed; if the collector cannot be reached the bootstrap file decides.
    func decideWizard() {
        guard !wizardDecided else { return }
        wizardDecided = true
        let args = CommandLine.arguments
        let flagDriven = args.contains { $0.hasPrefix("--dump") || $0.hasPrefix("--verify") || $0.hasPrefix("--security") || $0.hasPrefix("--register") || $0.hasPrefix("--unregister") || $0.hasPrefix("--export") || $0.hasPrefix("--backup") || $0 == "--skip-wizard" }
        showSetupWizard = args.contains("--show-wizard") || (!configuration.setupCompleted && !flagDriven)
    }

    // MARK: Navigation

    func openInvestigation(_ anchor: InvestigationAnchor, at time: Timestamp? = nil) {
        investigationAnchor = anchor
        investigationTime = time ?? anchor.time ?? .now
        requestedSection = .investigation
    }

    /// netsentry://alert/<id> and netsentry://client/<id> from notifications and other apps.
    func handle(url: URL) {
        guard url.scheme == Branding.urlScheme else { return }
        let parts = url.pathComponents.filter { $0 != "/" }
        switch (url.host, parts.first.flatMap(Int64.init)) {
        case ("alert", let id?): pendingAlertID = id; requestedSection = .security
        case ("client", let id?): openInvestigation(.client(id, label: "client \(id)", addresses: []))
        default: break
        }
    }

    // MARK: Storage access for analytics

    var storageRootPath: String {
        (health?.demoWorkspace ?? configuration.demoWorkspace) ? StorageLocations.demoStorageRoot().path : configuration.storageRoot
    }

    /// Saved searches live in meta.sqlite (the dashboard opens it read-write for its own tables only).
    func saveSearch(name: String, view: String, query: RecordFilter) {
        do {
            let store = try MetaStore(root: URL(fileURLWithPath: storageRootPath))
            let json = String(decoding: try JSONEncoder().encode(query), as: UTF8.self)
            try store.db.run("INSERT INTO saved_searches (name, view, query_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", [name, view, json, Timestamp.now, Timestamp.now])
        } catch { lastError = "Could not save search: \(error.localizedDescription)" }
    }

    func savedSearches(view: String) -> [(id: Int64, name: String, query: RecordFilter)] {
        guard let store = try? MetaStore(root: URL(fileURLWithPath: storageRootPath), readOnly: true) else { return [] }
        return (try? store.db.query("SELECT id, name, query_json FROM saved_searches WHERE view = ? ORDER BY name", [view]))?.compactMap { r in
            guard let json = r.string("query_json"), let q = try? JSONDecoder().decode(RecordFilter.self, from: Data(json.utf8)) else { return nil }
            return (r.int64("id") ?? 0, r.string("name") ?? "", q)
        } ?? []
    }

    // MARK: Live activity

    private func ingestLive(_ b: LiveBatch) {
        guard b.subscriptionID == liveSubscription else { return }
        if livePaused { livePausedDropped += b.flows.count + b.events.count + b.sampledOut; return }
        liveSampledOut += b.sampledOut
        var rows: [LiveRow] = []
        rows.reserveCapacity(b.flows.count + b.events.count)
        for f in b.flows { liveSequence += 1; rows.append(LiveRow(id: liveSequence, time: f.endTime, flow: f, event: nil)) }
        for e in b.events { liveSequence += 1; rows.append(LiveRow(id: liveSequence, time: e.effectiveTime, flow: nil, event: e)) }
        liveRows.insert(contentsOf: rows.reversed(), at: 0)
        if liveRows.count > Self.liveRingSize { liveRows.removeLast(liveRows.count - Self.liveRingSize) }
    }

    func subscribeLive() async {
        guard liveSubscription == nil else { return }
        log.info("subscribeLive: requesting")
        defer { log.info("subscribeLive: done (\(self.liveSubscription != nil))") }
        do {
            let reply = try await client.request(LiveSubscribeRequest(filter: LiveFilter(), maxPerSecond: configuration.liveMaxRecordsPerSecond))
            liveSubscription = reply.subscriptionID
        } catch { lastError = "Live stream: \(error.localizedDescription)" }
    }

    func unsubscribeLive() async {
        guard let id = liveSubscription else { return }
        liveSubscription = nil
        _ = try? await client.request(LiveUnsubscribeRequest(subscriptionID: id))
    }

    var liveSubscribed: Bool { liveSubscription != nil }

    func clearLive() { liveRows.removeAll(); liveSampledOut = 0; livePausedDropped = 0 }

    func setCollectorEnabled(_ enabled: Bool) async {
        var c = configuration
        c.collectionEnabled = enabled
        c.launchAtLogin = enabled
        _ = await apply(c)
        do {
            if enabled { try manager.register() } else { try await manager.unregister() }
        } catch {
            lastError = "Login item: \(error.localizedDescription)"
        }
        agentStatus = manager.statusDescription
        try? await Task.sleep(for: .seconds(1))
        await refresh()
    }
}


/// Posts alert notifications from the dashboard when the collector could not (see `AlertRaised.notified`).
@MainActor
final class DashboardNotifier: NSObject, UNUserNotificationCenterDelegate {
    private let center = UNUserNotificationCenter.current()
    private var authorized = false
    override init() {
        super.init()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound]) { [weak self] ok, _ in Task { @MainActor in self?.authorized = ok } }
    }
    func post(_ a: AlertRaised) {
        guard authorized else { return }
        let content = UNMutableNotificationContent()
        content.title = a.title; content.body = a.summary; content.userInfo = ["alertID": a.id]
        content.sound = a.severity >= .high ? .default : nil
        center.add(UNNotificationRequest(identifier: "alert-\(a.id)", content: content, trigger: nil))
    }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        let id = response.notification.request.content.userInfo["alertID"] as? Int64
        Task { @MainActor in if let id, let url = URL(string: "\(Branding.urlScheme)://alert/\(id)") { NSWorkspace.shared.open(url) } }
        completionHandler()
    }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}
