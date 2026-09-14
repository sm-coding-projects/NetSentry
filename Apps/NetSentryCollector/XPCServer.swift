import Foundation
import NetSentryCore
import NetSentryDetection
import NetSentryEnrichment
import NetSentryIPC
import NetSentryPersistence
import os

/// Accepts dashboard connections on the LaunchAgent's Mach service and routes envelopes to the service.
final class XPCServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let log = Log.logger("xpc", process: "collector")
    private let listener: NSXPCListener
    private let service: CollectorService
    private let clients = ClientRegistry()

    init(service: CollectorService) {
        self.service = service
        listener = NSXPCListener(machServiceName: Branding.machServiceName)
        super.init()
        listener.delegate = self
    }

    func start() {
        listener.resume()
        log.notice("XPC listener resumed for \(Branding.machServiceName, privacy: .public)")
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        #if DEBUG
        newConnection.setCodeSigningRequirement(XPCRequirement.dashboard(pinToTeam: false))
        #else
        newConnection.setCodeSigningRequirement(XPCRequirement.dashboard(pinToTeam: true))
        #endif
        newConnection.exportedInterface = NSXPCInterface(with: CollectorXPCProtocol.self)
        newConnection.remoteObjectInterface = NSXPCInterface(with: CollectorClientXPCProtocol.self)
        let handler = ConnectionHandler(service: service, connection: newConnection, clients: clients)
        newConnection.exportedObject = handler
        newConnection.invalidationHandler = { [weak handler] in handler?.invalidated() }
        newConnection.interruptionHandler = { [weak handler] in handler?.invalidated() }
        newConnection.resume()
        clients.add(newConnection)
        log.info("Dashboard connected (pid \(newConnection.processIdentifier))")
        return true
    }

    /// Pushes a notification to every connected dashboard.
    func broadcast<N: IPCNotification>(_ n: N) {
        guard let data = try? IPCCoding.encode(IPCEnvelope(kind: N.kind, payload: try IPCCoding.encode(n))) else { return }
        clients.broadcast(data)
    }
}

/// Sendable holder for a weak XPC connection used from live-batch delivery closures.
final class ConnectionBox: @unchecked Sendable {
    private weak var connection: NSXPCConnection?
    init(_ c: NSXPCConnection) { connection = c }
    func deliver(_ data: Data) {
        (connection?.remoteObjectProxyWithErrorHandler { _ in } as? CollectorClientXPCProtocol)?.deliver(data)
    }
}

final class ClientRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var connections: [NSXPCConnection] = []
    func add(_ c: NSXPCConnection) { lock.lock(); connections.append(c); lock.unlock() }
    func remove(_ c: NSXPCConnection) { lock.lock(); connections.removeAll { $0 === c }; lock.unlock() }
    func broadcast(_ data: Data) {
        lock.lock(); let cs = connections; lock.unlock()
        for c in cs {
            (c.remoteObjectProxyWithErrorHandler { _ in } as? CollectorClientXPCProtocol)?.deliver(data)
        }
    }
}

/// One dashboard connection: decodes envelopes, dispatches typed requests, tracks live subscriptions.
final class ConnectionHandler: NSObject, CollectorXPCProtocol, @unchecked Sendable {
    private let service: CollectorService
    private weak var connection: NSXPCConnection?
    private let clients: ClientRegistry
    private let log = Log.logger("xpc", process: "collector")
    private let subscriptions = OSAllocatedUnfairLock(initialState: Set<UUID>())
    private let box: ConnectionBox

    init(service: CollectorService, connection: NSXPCConnection, clients: ClientRegistry) {
        self.service = service
        self.connection = connection
        self.clients = clients
        self.box = ConnectionBox(connection)
    }

    func invalidated() {
        if let c = connection { clients.remove(c) }
        let subs = subscriptions.withLock { s in let x = s; s.removeAll(); return x }
        Task { await service.liveHub.removeAll(matching: subs) }
    }

    func send(_ envelopeData: Data, reply: @escaping @Sendable (Data) -> Void) {
        Task {
            let requestID: UUID
            let out: IPCReply
            do {
                let env = try IPCCoding.decode(IPCEnvelope.self, from: envelopeData)
                requestID = env.requestID
                try IPCCoding.validate(env)
                out = IPCReply(requestID: requestID, payload: try await self.dispatch(env))
            } catch let e as IPCError {
                out = IPCReply(requestID: UUID(), error: e)
            } catch {
                out = IPCReply(requestID: UUID(), error: .rejected(error.localizedDescription))
            }
            reply((try? IPCCoding.encode(out)) ?? Data())
        }
    }

    private func dispatch(_ env: IPCEnvelope) async throws -> Data {
        switch env.kind {
        case StatusRequest.kind:
            return try IPCCoding.encode(await service.snapshot())
        case ConfigGetRequest.kind:
            return try IPCCoding.encode(await service.configuration)
        case ConfigApplyRequest.kind:
            let req = try IPCCoding.decode(ConfigApplyRequest.self, from: env.payload)
            return try IPCCoding.encode(await service.apply(req.configuration))
        case ListenerTestRequest.kind:
            let req = try IPCCoding.decode(ListenerTestRequest.self, from: env.payload)
            return try IPCCoding.encode(await service.runListenerTest(kind: req.kind, seconds: req.seconds))
        case LiveSubscribeRequest.kind:
            let req = try IPCCoding.decode(LiveSubscribeRequest.self, from: env.payload)
            let box = self.box
            let id = await service.liveHub.subscribe(filter: req.filter, maxPerSecond: req.maxPerSecond) { batch in
                guard let data = try? IPCCoding.encode(IPCEnvelope(kind: LiveBatch.kind, payload: try IPCCoding.encode(batch))) else { return }
                box.deliver(data)
            }
            subscriptions.withLock { _ = $0.insert(id) }
            return try IPCCoding.encode(LiveSubscribeRequest.Reply(subscriptionID: id))
        case LiveUnsubscribeRequest.kind:
            let req = try IPCCoding.decode(LiveUnsubscribeRequest.self, from: env.payload)
            subscriptions.withLock { _ = $0.remove(req.subscriptionID) }
            await service.liveHub.unsubscribe(req.subscriptionID)
            return try IPCCoding.encode(Empty())
        case StorageStatusRequest.kind:
            guard let s = await service.storageSummary() else { throw IPCError.rejected("Storage is not open") }
            return try IPCCoding.encode(s)
        case RetentionPreviewRequest.kind:
            let req = try IPCCoding.decode(RetentionPreviewRequest.self, from: env.payload)
            let plan = try await service.retentionPlan(budget: req.budgetBytes)
            let reply = RetentionPreviewRequest.Reply(budgetBytes: plan.budgetBytes, usageBefore: plan.usageBefore, usageAfter: plan.usageAfter,
                                                      steps: plan.steps.map { .init(stage: $0.stage, description: $0.description, bytesFreed: $0.bytesFreed, segments: $0.segments,
                                                                                    oldestSurvivingFlow: $0.oldestSurvivingFlow, oldestSurvivingEvent: $0.oldestSurvivingEvent) },
                                                      removesRecentData: plan.removesRecentData)
            return try IPCCoding.encode(reply)
        case RetentionRunRequest.kind:
            await service.runRetention()
            guard let s = await service.storageSummary() else { throw IPCError.rejected("Storage is not open") }
            return try IPCCoding.encode(s)
        case StorageFlushRequest.kind:
            await service.flushStorage()
            guard let s = await service.storageSummary() else { throw IPCError.rejected("Storage is not open") }
            return try IPCCoding.encode(s)
        case SegmentsVerifyRequest.kind:
            let req = try IPCCoding.decode(SegmentsVerifyRequest.self, from: env.payload)
            return try IPCCoding.encode(SegmentsVerifyRequest.Reply(issues: await service.verifySegments(req.segmentIDs)))
        case SecurityRequest.kind:
            let req = try IPCCoding.decode(SecurityRequest.self, from: env.payload)
            return try IPCCoding.encode(SecurityRequest.Reply(json: try await SecurityOps.handle(req, service: service)))
        case GracefulShutdownRequest.kind:
            Task { await CollectorApp.shared.requestShutdown(reason: "requested by dashboard") }
            return try IPCCoding.encode(Empty())
        case HotQueryRequest.kind:
            let req = try IPCCoding.decode(HotQueryRequest.self, from: env.payload)
            return try IPCCoding.encode(await service.hotQuery(req))
        case DiagnosticsExportRequest.kind:
            let req = try IPCCoding.decode(DiagnosticsExportRequest.self, from: env.payload)
            return try IPCCoding.encode(DiagnosticsExportRequest.Reply(path: try await service.exportDiagnostics(includeTelemetry: req.includeTelemetry)))
        case StorageBackupRequest.kind:
            return try IPCCoding.encode(try await service.backupStore())
        default:
            throw IPCError.unknownKind(env.kind)
        }
    }
}



/// Security/entity operations exposed over XPC. Every op returns JSON; all mutations reload detection policy.
enum SecurityOps {
    static let enc: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .millisecondsSince1970; return e }()

    static func handle(_ req: SecurityRequest, service: CollectorService) async throws -> Data {
        guard let engine = await service.detectionEngine, let resolver = await service.entityResolver else { throw IPCError.rejected("Security engine is not running (storage not open).") }
        let store = await engine.alertStore
        func id() throws -> Int64 { guard let v = req.args["id"].flatMap(Int64.init) else { throw IPCError.rejected("missing id") }; return v }
        switch req.op {
        case "alerts.list":
            let states = req.args["states"]?.split(separator: ",").compactMap { AlertState(rawValue: String($0)) }
            let sev = req.args["severities"]?.split(separator: ",").compactMap { UInt8($0).flatMap(AlertSeverity.init) }
            return try enc.encode(try await store.alerts(states: states?.isEmpty == false ? states : nil, severities: sev?.isEmpty == false ? sev : nil, clientID: req.args["clientID"].flatMap(Int64.init), limit: Int(req.args["limit"] ?? "500") ?? 500))
        case "alerts.get": return try enc.encode(try await store.alert(id: try id()))
        case "alerts.counts": return try enc.encode(try await store.counts().reduce(into: [String: Int]()) { $0[$1.key.rawValue] = $1.value })
        case "alerts.setState":
            guard let st = req.args["state"].flatMap(AlertState.init) else { throw IPCError.rejected("bad state") }
            try await store.setState(try id(), st); return try enc.encode(try await store.alert(id: try id()))
        case "alerts.addNote": try await store.addNote(try id(), req.args["text"] ?? ""); return try enc.encode(try await store.alert(id: try id()))
        case "suppressions.list": return try enc.encode(try await store.suppressions())
        case "suppressions.add":
            let s = Suppression(ruleName: req.args["rule"].flatMap { $0.isEmpty ? nil : $0 } ?? "*", clientID: req.args["clientID"].flatMap(Int64.init), vlan: req.args["vlan"], destination: req.args["destination"],
                                port: req.args["port"].flatMap(Int.init), asn: req.args["asn"].flatMap(Int.init), country: req.args["country"],
                                startHour: req.args["startHour"].flatMap(Int.init), endHour: req.args["endHour"].flatMap(Int.init),
                                expiresAt: req.args["expiresAt"].flatMap(Int64.init).map { NetSentryCore.Timestamp(microseconds: $0) }, reason: req.args["reason"])
            _ = try await store.addSuppression(s); try await engine.reloadPolicy(); return try enc.encode(try await store.suppressions())
        case "suppressions.remove": try await store.removeSuppression(try id()); try await engine.reloadPolicy(); return try enc.encode(try await store.suppressions())
        case "expectations.list": return try enc.encode(try await store.expectations().map { ["id": "\($0.id)", "scopeType": $0.scopeType, "scopeValue": $0.scopeValue, "kind": $0.kind, "value": $0.value, "note": $0.note ?? ""] })
        case "expectations.add":
            try await store.addExpectation(scopeType: req.args["scopeType"] ?? "global", scopeValue: req.args["scopeValue"] ?? "*", kind: req.args["kind"] ?? "", value: req.args["value"] ?? "", note: req.args["note"])
            try await engine.reloadPolicy(); return try enc.encode(["ok": true])
        case "expectations.remove": try await store.removeExpectation(id: try id()); try await engine.reloadPolicy(); return try enc.encode(["ok": true])
        case "rules.list":
            let configs = try await store.ruleConfigurations()
            let rows = await engine.ruleDescriptors.map { d -> [String: String] in
                var row = ["name": d.name, "version": "\(d.version)", "title": d.title, "description": d.description, "severity": "\(d.severity.rawValue)", "enabled": "\(configs[d.name]?.enabled ?? true)"]
                row["parameters"] = String(decoding: (try? enc.encode(d.parameters.map { p in ["key": p.key, "label": p.label, "unit": p.unit, "help": p.help, "default": "\(p.value)", "value": "\(configs[d.name]?.parameters[p.key] ?? p.value)"] })) ?? Data("[]".utf8), as: UTF8.self)
                return row
            }
            return try enc.encode(rows)
        case "rules.set":
            guard let name = req.args["name"] else { throw IPCError.rejected("missing rule name") }
            var c = (try await store.ruleConfigurations())[name] ?? RuleConfiguration()
            if let e = req.args["enabled"] { c.enabled = e == "true" }
            for (k, v) in req.args where k.hasPrefix("param.") { if let d = Double(v) { c.parameters[String(k.dropFirst(6))] = d } }
            let version = await engine.ruleDescriptors.first { $0.name == name }?.version ?? 1
            try await store.setRuleConfiguration(name, version: version, c); try await engine.reloadPolicy(); return try enc.encode(["ok": true])
        case "clients.list": return try enc.encode(try await resolver.allClients())
        case "clients.get": return try enc.encode(try await resolver.client(id: try id()))
        case "clients.rename": try await resolver.rename(try id(), to: req.args["name"]); await service.refreshClientName(try id()); return try enc.encode(try await resolver.client(id: try id()))
        case "clients.setNotes": try await resolver.setNotes(try id(), req.args["notes"]); return try enc.encode(try await resolver.client(id: try id()))
        case "clients.setTags": try await resolver.setTags(try id(), (req.args["tags"] ?? "").split(separator: ",").map(String.init)); return try enc.encode(try await resolver.client(id: try id()))
        case "clients.setTrusted": try await resolver.setTrusted(try id(), req.args["trusted"] == "true"); return try enc.encode(try await resolver.client(id: try id()))
        case "clients.merge":
            guard let into = req.args["into"].flatMap(Int64.init) else { throw IPCError.rejected("missing target") }
            try await resolver.merge(try id(), into: into); await service.refreshClientName(into); return try enc.encode(try await resolver.client(id: into))
        case "clients.split":
            guard let ip = req.args["ip"].flatMap(IPAddress.init) else { throw IPCError.rejected("missing ip") }
            let newID = try await resolver.split(ip: ip, from: try id(), at: .now); await service.refreshClientName(newID); return try enc.encode(try await resolver.client(id: newID))
        case "detection.stats": return try enc.encode(await engine.stats)
        default: throw IPCError.unknownKind("security.op \(req.op)")
        }
    }
}
