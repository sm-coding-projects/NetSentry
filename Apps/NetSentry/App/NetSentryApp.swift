import AppKit
import SwiftUI
import NetSentryPersistence
import NetSentryIPC
import NetSentryCore


@main
struct NetSentryApp: App {
    @State private var model: AppModel
    @State private var analytics: AnalyticsService
    @State private var aiSettings: AISettings
    @State private var ai: AIService

    init() {
        #if DEBUG
        Self.handleCommandLineFlags()   // may exit; must run before AppModel touches SMAppService/XPC
        #endif
        let m = AppModel()
        _model = State(initialValue: m)
        let a = AnalyticsService()
        _analytics = State(initialValue: a)
        let settings = AISettings()
        _aiSettings = State(initialValue: settings)
        _ai = State(initialValue: AIService(settings: settings, model: m, analytics: a))

        #if DEBUG
        AppModelRegistry.shared = m
        #endif
    }

    #if DEBUG
    /// Developer affordance: exercise the real SMAppService path from the terminal.
    ///   NetSentry.app/Contents/MacOS/NetSentry --register-collector | --unregister-collector
    /// A watchdog exits with status 2 if ServiceManagement does not answer within 20 s.
    private static func handleCommandLineFlags() {

        let args = CommandLine.arguments
        if args.contains("--register-collector") || args.contains("--unregister-collector") {
            DispatchQueue.global().asyncAfter(deadline: .now() + 20) {
                writeCLIResult("timed out waiting for ServiceManagement"); print("timed out"); exit(2)
            }
            let manager = CollectorManager()
            var config = BootstrapConfig.loadOrCreate()
            config.collectionEnabled = args.contains("--register-collector")
            config.launchAtLogin = config.collectionEnabled
            try? BootstrapConfig.save(config)
            // Runs on the main thread before the run loop starts, so use the synchronous APIs only.
            do {
                if config.collectionEnabled {
                    try manager.register()
                } else {
                    let sema = DispatchSemaphore(value: 0)
                    manager.unregister { error in
                        if let error { print("failed: \(error)") }
                        sema.signal()
                    }
                    _ = sema.wait(timeout: .now() + 10)
                }
                let msg = "collector \(config.collectionEnabled ? "registered" : "unregistered"); status: \(manager.statusDescription)"
                print(msg); Self.writeCLIResult(msg)
            } catch {
                print("failed: \(error)"); Self.writeCLIResult("failed: \(error)")
            }
            exit(0)
        }
    }
    #endif

    #if DEBUG
    /// Developer affordance: `--dump-status <json path> [--after s]` writes the collector's HealthSnapshot and
    /// configuration as JSON (used by integration checks), then exits.
    @MainActor
    private static func runDumpStatusFlagIfRequested() async {
        let args = CommandLine.arguments
        Log.logger("cli", process: "app").notice("task started; args=\(args.dropFirst().joined(separator: " "), privacy: .public) registry=\(AppModelRegistry.shared != nil)")
        let after = args.firstIndex(of: "--after").flatMap { $0 + 1 < args.count ? Double(args[$0 + 1]) : nil } ?? 6
        // `--dump-live <json path> [--after s]`: subscribe to the sampled live stream, collect, write a summary, exit.
        if let i = args.firstIndex(of: "--dump-live"), i + 1 < args.count, let model = AppModelRegistry.shared {
            let log = Log.logger("cli", process: "app")
            await model.subscribeLive()
            log.notice("dump-live: subscribed=\(model.liveSubscribed) error=\(model.lastError ?? "none", privacy: .public)")
            try? await Task.sleep(for: .seconds(after))
            await model.unsubscribeLive()
            let rows = model.liveRows
            let flows = rows.compactMap(\.flow), events = rows.compactMap(\.event)
            var out: [String: Any] = ["rows": rows.count, "flows": flows.count, "events": events.count, "sampledOut": model.liveSampledOut,
                                      "error": model.lastError ?? ""]
            out["sampleFlows"] = flows.prefix(5).map { f in FlowFields.describe(f).map { "\($0.0)=\($0.1)" } }
            out["sampleEvents"] = events.prefix(5).map { e in EventFields.describe(e).map { "\($0.0)=\($0.1)" } }
            out["directions"] = Dictionary(grouping: flows, by: { $0.enrichment.direction.label }).mapValues(\.count)
            out["eventTypes"] = Dictionary(grouping: events, by: { $0.eventType.label }).mapValues(\.count)
            do {
                let data = try JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys])
                try data.write(to: URL(fileURLWithPath: args[i + 1]))
                log.notice("dump-live: wrote \(rows.count) rows")
            } catch {
                log.error("dump-live failed: \(String(describing: error), privacy: .public)")
            }
            exit(0)
        }
        // `--dump-overview <json path> [--after s]`: run the Overview aggregates over the store and write them out.
        if let i = args.firstIndex(of: "--dump-overview"), i + 1 < args.count, let model = AppModelRegistry.shared {
            try? await Task.sleep(for: .seconds(after))
            let svc = AnalyticsService()
            let loader = OverviewLoader()
            loader.load(analytics: svc, root: URL(fileURLWithPath: model.storageRootPath), preset: .h1, origin: .live)
            var waited = 0.0
            while loader.loading || (loader.data == nil && loader.error == nil), waited < 60 { try? await Task.sleep(for: .milliseconds(200)); waited += 0.2 }
            var out: [String: Any] = ["error": loader.error ?? svc.openError ?? ""]
            if let d = loader.data {
                out["seriesBuckets"] = d.series.count; out["totalBytes"] = d.totals?.bytes ?? 0; out["totalFlows"] = d.totals?.flows ?? 0
                out["topClients"] = d.topClients.prefix(3).map { "\($0.key) \($0.bytes)" }; out["topDestinations"] = d.topDestinations.prefix(3).map { "\($0.key) \($0.bytes)" }
                out["topPorts"] = d.topPorts.prefix(5).map { "\($0.key) \($0.flows)" }; out["eventsByType"] = d.eventsByType.map { "\($0.key)=\($0.count)" }
                out["eventsByAction"] = d.eventsByAction.map { "\($0.key)=\($0.count)" }; out["gaps"] = d.gaps.count; out["elapsedMs"] = Double(d.elapsed.components.seconds) * 1000 + Double(d.elapsed.components.attoseconds) / 1e15
            }
            if let data = try? JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys]) { try? data.write(to: URL(fileURLWithPath: args[i + 1])) }
            exit(0)
        }
        // `--verify-storage <json path>`: full segment verification through the collector, then exit.
        if let i = args.firstIndex(of: "--verify-storage"), i + 1 < args.count {
            try? await Task.sleep(for: .seconds(after))
            let client = CollectorClient()
            var out: [String: Any] = [:]
            do {
                let r = try await client.request(SegmentsVerifyRequest(), timeout: .seconds(600))
                out["issues"] = r.issues
                let s = try await client.request(StorageStatusRequest())
                out["storage"] = try JSONSerialization.jsonObject(with: IPCCoding.encode(s))
            } catch { out["error"] = String(describing: error) }
            if let data = try? JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys]) { try? data.write(to: URL(fileURLWithPath: args[i + 1])) }
            exit(0)
        }
        // `--security-op <json path> <op> [key=value ...]`: run one security/entity operation (e.g. rules.set name=first-seen-destination param.learningDays=0).
        if let i = args.firstIndex(of: "--security-op"), i + 2 < args.count {
            try? await Task.sleep(for: .seconds(after))
            var kv: [String: String] = [:]
            for a in args[(i + 3)...] where a.contains("=") { let p = a.split(separator: "=", maxSplits: 1); kv[String(p[0])] = String(p[1]) }
            var out: [String: Any] = ["op": args[i + 2], "args": kv]
            do { let r = try await CollectorClient().request(SecurityRequest(op: args[i + 2], args: kv), timeout: .seconds(30)); out["reply"] = try JSONSerialization.jsonObject(with: r.json, options: [.fragmentsAllowed]) }
            catch { out["error"] = String(describing: error) }
            if let data = try? JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys]) { try? data.write(to: URL(fileURLWithPath: args[i + 1])) }
            exit(0)
        }
        // `--export-diagnostics <json path>` / `--backup-store <json path>`: run the collector-side export and report the zip path.
        for (flag, run) in [("--export-diagnostics", { () async throws -> [String: Any] in let r = try await CollectorClient().request(DiagnosticsExportRequest(includeTelemetry: true), timeout: .seconds(300)); return ["path": r.path] }),
                            ("--backup-store", { () async throws -> [String: Any] in let r = try await CollectorClient().request(StorageBackupRequest(), timeout: .seconds(120)); return ["path": r.path, "bytes": r.bytes] })] {
            if let i = args.firstIndex(of: flag), i + 1 < args.count {
                try? await Task.sleep(for: .seconds(after))
                var out: [String: Any]
                do { out = try await run() } catch { out = ["error": String(describing: error)] }
                if let data = try? JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys]) { try? data.write(to: URL(fileURLWithPath: args[i + 1])) }
                exit(0)
            }
        }
        // `--dump-security <json path>`: alerts, clients, rules and detection stats through the collector's security ops.
        if let i = args.firstIndex(of: "--dump-security"), i + 1 < args.count {
            try? await Task.sleep(for: .seconds(after))
            let sec = SecurityClient(client: CollectorClient())
            var out: [String: Any] = [:]
            do {
                let alerts = try await sec.alerts()
                out["alertCount"] = alerts.count
                out["alerts"] = alerts.prefix(20).map { "\($0.id) [\($0.severity.label)/\($0.state.rawValue)] \($0.ruleName): \($0.title) x\($0.occurrenceCount)" }
                out["counts"] = try await sec.counts()
                let clients = try await sec.clients()
                out["clientCount"] = clients.count
                out["clients"] = clients.prefix(25).map { "\($0.id) \($0.label) addrs=\($0.addresses) mac=\($0.primaryMAC ?? "-") vlan=\($0.vlanID.map(String.init) ?? "-") host=\($0.hostname ?? "-")" }
                out["rules"] = try await sec.rules().map { "\($0["name"] ?? "") enabled=\($0["enabled"] ?? "")" }
                let st = try await sec.detectionStats()
                out["stats"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(st))
                out["expectations"] = try await sec.expectations().count
                out["suppressions"] = try await sec.suppressions().count
            } catch { out["error"] = String(describing: error) }
            if let data = try? JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys]) { try? data.write(to: URL(fileURLWithPath: args[i + 1])) }
            exit(0)
        }
        if let i = args.firstIndex(of: "--dump-status"), i + 1 < args.count {
            try? await Task.sleep(for: .seconds(after))
            let client = CollectorClient()
            var out: [String: Any] = [:]
            do {
                let h: HealthSnapshot = try await client.request(StatusRequest())
                let c: CollectorConfiguration = try await client.request(ConfigGetRequest())
                out["health"] = try JSONSerialization.jsonObject(with: IPCCoding.encode(h))
                out["configuration"] = try JSONSerialization.jsonObject(with: IPCCoding.encode(c))
            } catch { out["error"] = String(describing: error) }
            if let data = try? JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys]) {
                try? data.write(to: URL(fileURLWithPath: args[i + 1]))
            }
            exit(0)
        }
    }

    private static func writeCLIResult(_ text: String) {
        let url = StorageLocations.sharedSupportDirectory().appending(path: "cli-result.txt")
        let line = Data("\(Date()) \(text)\n".utf8)
        if let h = try? FileHandle(forWritingTo: url) { _ = try? h.seekToEnd(); try? h.write(contentsOf: line); try? h.close() }
        else { try? line.write(to: url) }
    }
    #endif

    var body: some Scene {
        WindowGroup {
            MainView()
                .environment(model)
                .environment(analytics)
                .environment(aiSettings)
                .environment(ai)
                .frame(minWidth: 1000, minHeight: 640)
                .task {
                    #if DEBUG
                    await Self.runDumpStatusFlagIfRequested()
                    #endif
                }
                .onOpenURL { model.handle(url: $0) }
        }
        .windowStyle(.automatic)
        .commands {
            SidebarCommands()
            CommandGroup(replacing: .newItem) {}
        }
        Settings {
            SettingsView()
                .environment(model)
                .environment(aiSettings)
                .environment(ai)
                .frame(width: 620)
        }
    }
}


#if DEBUG
/// Lets developer flags reach the live model without threading it through the scene.
@MainActor enum AppModelRegistry { static var shared: AppModel? }
#endif
