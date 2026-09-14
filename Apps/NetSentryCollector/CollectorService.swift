import Foundation
import NetSentryCore
import NetSentryIPC
import NetSentryDetection
import NetSentryEnrichment
import NetSentryIPFIX
import NetSentryPersistence
import NetSentrySyslog
import os

/// Assembles and owns the pipeline: listeners → receive queue → decode stage (Phase 2) → … .
/// Configuration changes are applied here; every change restarts only the affected listeners.
actor CollectorService {
    private let log = Log.logger("service", process: "collector")
    let health = HealthMonitor()
    private(set) var configuration: CollectorConfiguration
    private var meta: MetaStore?
    private var listeners: [String: NetworkListener] = [:]
    private let receiveQueue = SyncBoundedQueue<RawDatagram>(name: "receive", capacity: 8_192)
    /// Decoded batches waiting for dispatch (health, live, persistence). `.suspend` applies backpressure to
    /// the decode task; the receive queue then absorbs bursts and drops newest when even that fills.
    private let decodedQueue = BoundedQueue<DecodedBatch>(name: "decoded", capacity: 64, policy: .suspend)
    private var drainTask: Task<Void, Never>?
    private var dispatchTask: Task<Void, Never>?
    private var tickTask: Task<Void, Never>?
    private var lastReportedDrops: UInt64 = 0
    private var listenerDelegate: ListenerBridge!
    private var isRunning = false
    private var testObservers: [UUID: ListenerTestAccumulator] = [:]
    private let live = LiveHub()
    private var capture: RawCaptureWriter?
    private let decoder = DecodeStage()
    private var classifier: DirectionClassifier
    private var lastExporterPublish = Timestamp(microseconds: 0)
    private var syslogSources: [IPAddress: ExporterStatus] = [:]
    private var storage: StorageManager?
    private var storageGapOpen = false
    private var ipfixExporterIDs: [ExporterKey: Int32] = [:]
    private var lastCompaction = Timestamp.now
    private var hotFlows: HotBuffer<FlowRecord>
    private var hotEvents: HotBuffer<SyslogEvent>
    private var resolver: EntityResolver?
    private var enricher: Enricher?
    private var detection: DetectionEngine?
    private var lastResolverFlush = Timestamp.now
    private var clientNameCache: [Int64: String] = [:]
    var onAlert: (@Sendable (Alert, Bool) -> Void)?

    init(configuration: CollectorConfiguration) {
        self.configuration = configuration
        self.classifier = DirectionClassifier(internalPrefixes: configuration.internalPrefixes)
        hotFlows = HotBuffer(maxRecords: configuration.hotBufferMaxRecords, maxAge: .seconds(configuration.hotBufferSeconds))
        hotEvents = HotBuffer(maxRecords: max(1_000, configuration.hotBufferMaxRecords / 4), maxAge: .seconds(configuration.hotBufferSeconds))
    }

    // MARK: Lifecycle

    func start() async {
        guard !isRunning else { return }
        isRunning = true
        listenerDelegate = ListenerBridge(service: self)
        await openMetaStore()
        let decodedQueue = self.decodedQueue
        await health.setQueueStatsProvider { [receiveQueue] in [receiveQueue.stats] }
        await health.setAsyncQueueStatsProvider { await [decodedQueue.stats] }
        await health.setStorageProvider { [weak self] in await self?.storageSummary() }
        drainTask = Task.detached(priority: .userInitiated) { [weak self] in await self?.drainLoop() }
        dispatchTask = Task.detached(priority: .utility) { [weak self] in await self?.dispatchLoop() }
        tickTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self else { return }
                await self.health.tick()
                await self.reportDrops()
                await self.storageTick()
                await self.detectionTick()
            }
        }
        await applyListeners()
        log.notice("Collector started (pid \(ProcessInfo.processInfo.processIdentifier))")
    }

    func stop() async {
        guard isRunning else { return }
        isRunning = false
        log.notice("Collector stopping; draining queues")
        for (_, l) in listeners { l.stop() }
        listeners.removeAll()
        receiveQueue.close()
        await drainTask?.value
        await decodedQueue.close()
        await dispatchTask?.value
        await capture?.closeAll()
        await storage?.closeGracefully()
        tickTask?.cancel()
        if let meta {
            try? await meta.openGap(kind: .collectorDown, reason: "Collector stopped")
            await meta.checkpoint()
        }
        log.notice("Collector stopped")
    }

    private func openMetaStore() async {
        let root = URL(fileURLWithPath: configuration.demoWorkspace ? StorageLocations.demoStorageRoot().path : configuration.storageRoot)
        do {
            if let old = storage { await old.closeGracefully() }
            let manager = try await StorageManager(root: root, policy: .init(configuration: configuration))
            storage = manager
            let store = manager.meta
            meta = store
            capture = RawCaptureWriter(storeRoot: root, config: configuration.diagnosticCapture)
            // Everything left open belongs to a previous run: close it, then record the downtime since the newest data.
            try await store.closeAllOpenGaps()
            if let newest = await manager.summary().newestRecord, Timestamp.now.microseconds - newest.microseconds > 120_000_000 {
                let id = try await store.openGap(kind: .collectorDown, reason: "Collector was not running", at: newest)
                try await store.closeGap(id: id)
            }
            await health.attach(meta: store, demo: configuration.demoWorkspace)
            let res = try await EntityResolver(meta: store, internalPrefixes: configuration.internalPrefixes)
            resolver = res
            enricher = Enricher(resolver: res, geoDatabasePath: configuration.geoIP.cityDatabasePath, asnDatabasePath: configuration.geoIP.asnDatabasePath)
            let det = try await DetectionEngine(meta: store)
            await det.configure(trustedResolvers: configuration.trustedResolvers.compactMap(IPAddress.init), internalPrefixes: configuration.internalPrefixes,
                                origin: configuration.demoWorkspace ? .simulated : .live)
            for c in try await res.allClients() { await det.setClientName(c.id, c.label); clientNameCache[c.id] = c.label }
            let cb = onAlert
            await det.setOnAlert { alert, isNew in cb?(alert, isNew) }
            detection = det
            for issue in await manager.recoveryReport { log.notice("Recovery: \(issue, privacy: .public)") }
            if !(await manager.integrityIssues).isEmpty {
                await health.setWarning(HealthWarning(id: "integrity", level: .warning, title: "Storage integrity issues found at startup",
                                                      detail: (await manager.integrityIssues).joined(separator: "; "), since: .now))
            }
            log.notice("Storage opened at \(root.path, privacy: .public)")
        } catch {
            log.error("Cannot open metadata store: \(error.localizedDescription, privacy: .public)")
            await health.setWarning(HealthWarning(id: "meta", level: .critical, title: "Storage unavailable",
                                                  detail: error.localizedDescription, since: .now))
        }
    }

    // MARK: Configuration

    func apply(_ new: CollectorConfiguration) async -> ConfigApplyRequest.Reply {
        let errors = new.validate()
        guard errors.isEmpty else { return .init(accepted: false, errors: errors, restartedListeners: []) }
        let old = configuration
        configuration = new
        classifier = DirectionClassifier(internalPrefixes: new.internalPrefixes)
        try? BootstrapConfig.save(new)
        if let meta { try? await meta.saveConfiguration(new) }
        if old.storageRoot != new.storageRoot || old.demoWorkspace != new.demoWorkspace {
            await openMetaStore()
        } else {
            if old.diagnosticCapture != new.diagnosticCapture { await capture?.update(new.diagnosticCapture) }
            await storage?.update(policy: .init(configuration: new))
            if old.geoIP != new.geoIP { await enricher?.setDatabases(geoPath: new.geoIP.cityDatabasePath, asnPath: new.geoIP.asnDatabasePath) }
            await detection?.configure(trustedResolvers: new.trustedResolvers.compactMap(IPAddress.init), internalPrefixes: new.internalPrefixes, origin: new.demoWorkspace ? .simulated : .live)
        }
        var restarted: [String] = []
        if old.listeners != new.listeners || old.collectionEnabled != new.collectionEnabled {
            restarted = await applyListeners()
        }
        return .init(accepted: true, errors: [], restartedListeners: restarted)
    }

    /// Starts/stops listeners so the running set matches the configuration. Returns ids restarted.
    @discardableResult
    private func applyListeners() async -> [String] {
        var changed: [String] = []
        let wanted = configuration.collectionEnabled ? configuration.listeners.filter(\.enabled) : []
        let wantedIDs = Set(wanted.map(\.id))
        for (id, l) in listeners where !wantedIDs.contains(id) || l.configuration != wanted.first(where: { $0.id == id }) {
            l.stop()
            listeners.removeValue(forKey: id)
            await health.removeListener(id: id)
            changed.append(id)
        }
        for cfg in wanted where listeners[cfg.id] == nil {
            let l = NetworkListener(configuration: cfg, delegate: listenerDelegate)
            listeners[cfg.id] = l
            await health.setListener(ListenerStatus(kind: cfg.kind, transport: cfg.transport, port: cfg.port, interface: cfg.interface, state: .starting))
            l.start()
            if !changed.contains(cfg.id) { changed.append(cfg.id) }
        }
        for cfg in configuration.listeners where !cfg.enabled || !configuration.collectionEnabled {
            await health.setListener(ListenerStatus(kind: cfg.kind, transport: cfg.transport, port: cfg.port, interface: cfg.interface, state: .disabled))
        }
        if !configuration.collectionEnabled {
            await health.openGap(.listenerDown, reason: "Collection disabled in settings")
        } else if listeners.isEmpty {
            await health.openGap(.listenerDown, reason: "No listeners enabled")
        }
        return changed
    }

    // MARK: Receive path (called from the listener queue via ListenerBridge)

    nonisolated func enqueue(_ datagram: RawDatagram) {
        // Never block the socket: the sync queue drops newest when full and counts it.
        receiveQueue.enqueue(datagram)
    }

    private func reportDrops() async {
        let dropped = receiveQueue.stats.dropped
        if dropped > lastReportedDrops {
            await health.recordReceiveDrops(dropped - lastReportedDrops)
            lastReportedDrops = dropped
        }
    }

    func listenerStateChanged(_ cfg: ListenerConfiguration, state: ListenerState) async {
        await health.setListener(ListenerStatus(kind: cfg.kind, transport: cfg.transport, port: cfg.port, interface: cfg.interface, state: state))
    }

    func connectionCountChanged(_ cfg: ListenerConfiguration, count: Int) async {
        await health.setConnectionCount(id: cfg.id, count: count)
    }

    /// Stage 1 consumer: drains the receive queue in micro-batches, accounts, captures, decodes and
    /// classifies, then hands the batch to the dispatch stage (suspending when it is behind).
    private func drainLoop() async {
        while true {
            let batch = await receiveQueue.dequeueBatch(max: 512)
            if batch.isEmpty { return }   // closed
            var accepted: [RawDatagram] = []
            accepted.reserveCapacity(batch.count)
            for d in batch {
                await health.record(datagram: d)
                if configuration.allowedExporterAddresses.isEmpty == false,
                   !configuration.allowedExporterAddresses.contains(d.source.description) {
                    await health.update { $0.rejected += 1 }
                    continue
                }
                if let capture, await capture.isEnabled { await capture.write(d) }
                accepted.append(d)
            }
            guard !accepted.isEmpty else { continue }
            var decoded = await decoder.decode(accepted)
            for i in decoded.flows.indices { classifier.classify(&decoded.flows[i]) }
            for i in decoded.events.indices { classifier.classify(&decoded.events[i]) }
            decoded.raw = accepted
            await decodedQueue.enqueue(decoded)
        }
    }

    /// Stage 2 consumer: health, listener tests, live subscribers, and (Phase 3) persistence.
    private func dispatchLoop() async {
        while true {
            let batches = await decodedQueue.dequeueBatch(max: 8)
            if batches.isEmpty { return }
            for var decoded in batches {
                await applyDecodeHealth(decoded, batch: decoded.raw)
                for (_, t) in testObservers { t.record(batch: decoded.raw, decoded: decoded) }
                await enrich(&decoded)
                await persist(&decoded)
                if let detection { await detection.evaluate(flows: decoded.flows, events: decoded.events) }
                for f in decoded.flows { hotFlows.append(f, at: f.endTime) }
                for e in decoded.events { hotEvents.append(e, at: e.effectiveTime) }
                await live.publish(flows: decoded.flows, events: decoded.events)
            }
        }
    }

    /// Maps decode results onto counters, warnings and exporter status.
    private func applyDecodeHealth(_ d: DecodedBatch, batch: [RawDatagram]) async {
        var malformed: UInt64 = 0, missing: UInt64 = 0, buffered: UInt64 = 0, gaps: UInt64 = 0
        var unsupported: Set<UInt16> = []
        var restarts: [ExporterKey] = []
        for e in d.ipfixEvents {
            switch e {
            case .malformed: malformed += 1
            case .unsupportedVersion(let v): unsupported.insert(v); malformed += 1
            case .missingTemplate(_, _, _, let wasBuffered): missing += 1; if wasBuffered { buffered += 1 }
            case .sequenceGap(_, _, _, let n) where n > 0: gaps += 1
            case .exporterRestart(let k, _): restarts.append(k)
            case .templateRejected(let k, let id, let reason):
                await health.setWarning(HealthWarning(id: "tmpl-\(k)-\(id)", level: .warning, title: "Template \(id) from \(k) rejected", detail: reason, since: .now))
            case .clockSkew(let k, let skew):
                await health.setWarning(HealthWarning(id: "skew-\(k)", level: .warning, title: "Exporter clock differs from this Mac",
                                                      detail: String(format: "%@ is %.0f s %@ this Mac's clock.", k.description, abs(Double(skew)) / 1e6, skew > 0 ? "ahead of" : "behind"), since: .now))
            default: break
            }
        }
        let flows = UInt64(d.flows.count), events = UInt64(d.events.count), unparsed = UInt64(d.unparsedEvents)
        await health.update { c in
            c.flowsDecoded += flows; c.eventsDecoded += events; c.malformed += malformed
            c.missingTemplate += missing; c.bufferedPendingTemplate += buffered; c.sequenceGaps += gaps
            c.parserFailures += unparsed; c.enriched += flows + events
        }
        for v in unsupported {
            await health.setWarning(HealthWarning(id: "netflow-v\(v)", level: .critical, title: "Gateway is sending NetFlow v\(v), not IPFIX",
                                                  detail: "NetSentry decodes IPFIX (NetFlow v10) only. Change the export format on the gateway to IPFIX.", since: .now))
        }
        for k in restarts {
            await health.setWarning(HealthWarning(id: "restart-\(k)", level: .info, title: "Exporter \(k) restarted", detail: "Sequence numbers or system init time reset.", since: .now))
        }
        // Exporter status (IPFIX from decoder state; syslog by source address), at most once per second.
        let now = Timestamp.now
        for dg in batch where dg.kind == .syslog {
            var st = syslogSources[dg.source] ?? ExporterStatus(kind: .syslog, key: ExporterKey(address: dg.source, observationDomain: 0), firstSeen: dg.receivedAt, lastSeen: dg.receivedAt)
            st.lastSeen = dg.receivedAt; st.messages += 1; st.records += 1
            syslogSources[dg.source] = st
        }
        if now.microseconds - lastExporterPublish.microseconds > 1_000_000 {
            lastExporterPublish = now
            for st in await decoder.exporterStates {
                await health.setExporter(ExporterStatus(kind: .ipfix, key: st.key, firstSeen: st.firstSeen, lastSeen: st.lastSeen, messages: st.messages,
                                                        records: st.records, lastSequence: st.lastSequence, sequenceGaps: st.sequenceGaps, restarts: st.restarts,
                                                        templates: st.templates.count, pendingUndecodable: st.pendingSets, clockSkewMicroseconds: st.clockSkewMicroseconds))
                if let meta, ipfixExporterIDs[st.key] == nil || st.messages % 60 == 0,
                   let id = try? await meta.upsertExporter(kind: .ipfix, key: st.key, seenAt: st.lastSeen, lastSequence: st.lastSequence, restarted: false) {
                    ipfixExporterIDs[st.key] = id
                }
                if st.pendingSets > 0 {
                    await health.setWarning(HealthWarning(id: "pending-\(st.key)", level: .warning, title: "Waiting for IPFIX templates from \(st.key)",
                                                          detail: "\(st.pendingSets) data sets are buffered until their template arrives (gateways resend templates periodically).", since: .now))
                } else { await health.clearWarning("pending-\(st.key)") }
            }
            for st in syslogSources.values { await health.setExporter(st) }
        }
    }

    // MARK: Enrichment

    private func enrich(_ decoded: inout DecodedBatch) async {
        guard let enricher, let resolver else { return }
        for i in decoded.flows.indices { await enricher.enrich(&decoded.flows[i]) }
        for i in decoded.events.indices { await enricher.enrich(&decoded.events[i]) }
        let changes = await resolver.drainChanges()
        if !changes.isEmpty, let detection {
            for c in changes where c.kind == .created || c.kind == .hostnameLearned {
                if let client = try? await resolver.client(id: c.clientID) { clientNameCache[c.clientID] = client.label; await detection.setClientName(c.clientID, client.label) }
            }
        }
        let now = Timestamp.now
        if now.microseconds - lastResolverFlush.microseconds > 30_000_000 { lastResolverFlush = now; try? await resolver.flushLastSeen() }
    }

    // MARK: Persistence

    private func persist(_ decoded: inout DecodedBatch) async {
        guard let storage else { return }
        do {
            try await storage.ingest(flows: &decoded.flows, events: &decoded.events, exporters: ipfixExporterIDs)
            let stored = UInt64(decoded.flows.count + decoded.events.count)
            await health.update { $0.stored += stored }
            if storageGapOpen, !(await storage.ingestionPaused) {
                storageGapOpen = false
                await health.closeGap(.diskPressure)
                await health.clearWarning("disk-pressure")
            }
        } catch {
            await health.update { $0.storageWriteFailures += 1 }
            if case StorageError.diskPressure(let free, let threshold) = error {
                if !storageGapOpen {
                    storageGapOpen = true
                    await health.openGap(.diskPressure, reason: "Free space below safety threshold", details: ["free": "\(free)", "threshold": "\(threshold)"])
                    await health.setWarning(HealthWarning(id: "disk-pressure", level: .critical, title: "Ingestion paused: disk nearly full",
                                                          detail: "Free space is \(free / 1_000_000_000) GB, below the safety threshold of \(threshold / 1_000_000_000) GB. Free space or lower the budget.", since: .now))
                }
            } else {
                await health.setWarning(HealthWarning(id: "storage-write", level: .critical, title: "Storage write failed", detail: error.localizedDescription, since: .now))
            }
        }
    }

    private var healthTicks = 0
    private func detectionTick() async {
        healthTicks += 1
        guard healthTicks % 10 == 0, let detection else { return }   // every 10 s
        await detection.evaluate(health: await health.snapshot())
    }

    /// User-facing entity and alert operations (called from XPC).
    var entityResolver: EntityResolver? { resolver }
    var detectionEngine: DetectionEngine? { detection }
    func refreshClientName(_ id: Int64) async {
        if let resolver, let c = try? await resolver.client(id: id) { clientNameCache[id] = c.label; await detection?.setClientName(id, c.label) }
    }
    func reloadDetectionPolicy() async { try? await detection?.reloadPolicy() }
    func setOnAlert(_ cb: @escaping @Sendable (Alert, Bool) -> Void) async {
        onAlert = cb
        await detection?.setOnAlert(cb)
    }

    private func storageTick() async {
        let now = Timestamp.now
        hotFlows.evict(now: now)
        hotEvents.evict(now: now)
        guard let storage else { return }
        await storage.tick()
        if now.microseconds - lastCompaction.microseconds > 600_000_000 {   // every 10 minutes
            lastCompaction = now
            Task.detached(priority: .utility) { await storage.compact() }
        }
    }

    // MARK: Requests

    func snapshot() async -> HealthSnapshot { await health.snapshot() }

    func storageSummary() async -> StorageSummary? {
        if let storage { return await storage.summary() }
        let root = configuration.demoWorkspace ? StorageLocations.demoStorageRoot().path : configuration.storageRoot
        let attrs = try? FileManager.default.attributesOfFileSystem(forPath: root)
        return StorageSummary(root: root, budgetBytes: configuration.budgetBytes, usedBytes: Self.directorySize(root),
                              freeBytesOnVolume: (attrs?[.systemFreeSize] as? Int64) ?? 0,
                              safetyThresholdBytes: configuration.safetyThreshold.bytes(forVolumeSize: (attrs?[.systemSize] as? Int64) ?? 0))
    }

    func retentionPlan(budget: Int64) async throws -> RetentionPlan {
        guard let storage else { throw IPCError.rejected("Storage is not open") }
        return try await storage.plan(budget: budget)
    }

    func runRetention() async { await storage?.enforceBudget() }

    /// Recent records from memory (last `hotBufferSeconds`), newest first, filtered by client address and text.
    func hotQuery(_ q: HotQueryRequest) -> HotQueryRequest.Reply {
        let (flows, tf) = hotFlows.query(from: q.start, to: q.end, limit: q.filter.flows ? q.limit : 0)
        let (events, te) = hotEvents.query(from: q.start, to: q.end, limit: q.filter.events ? q.limit : 0)
        let ip = q.filter.clientIP.flatMap(IPAddress.init)
        let text = q.filter.text?.lowercased()
        let f = flows.filter { fl in
            (ip == nil || fl.srcIP == ip! || fl.dstIP == ip!) &&
            (text == nil || "\(fl.srcIP) \(fl.dstIP) \(fl.dstPort) \(fl.protocolName)".lowercased().contains(text!))
        }
        let e = events.filter { ev in
            (ip == nil || ev.srcIP == ip! || ev.dstIP == ip! || ev.sourceIP == ip!) &&
            (text == nil || (ev.message + " " + (ev.ruleName ?? "") + " " + (ev.idsSignature ?? "")).lowercased().contains(text!))
        }
        return .init(flows: f, events: e, truncated: tf || te)
    }
    func verifySegments(_ ids: [Int64]?) async -> [String] { await storage?.verify(segmentIDs: ids) ?? ["Storage is not open"] }
    func flushStorage() async { await storage?.flushAll() }

    /// Allocated bytes under `path` (synchronous; NSEnumerator cannot be iterated from async code).
    nonisolated static func directorySize(_ path: String) -> Int64 {
        var used: Int64 = 0
        guard let e = FileManager.default.enumerator(at: URL(fileURLWithPath: path), includingPropertiesForKeys: [.totalFileAllocatedSizeKey], options: [.skipsHiddenFiles]) else { return 0 }
        while let u = e.nextObject() as? URL {
            used += Int64((try? u.resourceValues(forKeys: [.totalFileAllocatedSizeKey]).totalFileAllocatedSize) ?? 0)
        }
        return used
    }

    // MARK: Diagnostics and backup

    private var storeRoot: URL { URL(fileURLWithPath: configuration.demoWorkspace ? StorageLocations.demoStorageRoot().path : configuration.storageRoot) }

    private static let stampFormatter: DateFormatter = { let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss"; f.locale = Locale(identifier: "en_US_POSIX"); return f }()

    /// Writes a zip with health, configuration (secrets stripped), storage status, verification, manifest counts,
    /// system facts and the last two hours of NetSentry log lines; optionally the newest raw capture and a manifest backup.
    func exportDiagnostics(includeTelemetry: Bool) async throws -> String {
        let stamp = Self.stampFormatter.string(from: Date())
        let dir = storeRoot.appending(path: "diagnostics/netsentry-diagnostics-\(stamp)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        func write(_ name: String, _ data: Data) throws { try data.write(to: dir.appending(path: name), options: .atomic) }
        try write("health.json", try enc.encode(await health.snapshot()))
        var cfg = configuration; cfg.geoIP.licenseKeyKeychainRef = nil
        try write("configuration.json", try enc.encode(cfg))
        if let s = await storageSummary() { try write("storage.json", try enc.encode(s)) }
        try write("verification.json", try enc.encode(await verifySegments(nil)))
        if let store = await storage?.meta {
            let u = try await store.segmentUsage()
            let usage: [String: Any] = ["flowBytes": u.flows, "eventBytes": u.events, "rawBytes": u.raw, "segments": u.count,
                                        "oldest": u.oldest.map { $0.date.description } ?? "", "newest": u.newest.map { $0.date.description } ?? ""]
            try write("manifest-usage.json", try JSONSerialization.data(withJSONObject: usage, options: [.prettyPrinted, .sortedKeys]))
            let gaps = try await store.gaps(from: Timestamp(microseconds: Timestamp.now.microseconds - 7 * 86_400_000_000), to: .now)
            try write("gaps-7d.json", try enc.encode(gaps))
            if includeTelemetry { let b = try await store.backupMeta(); try FileManager.default.copyItem(at: b, to: dir.appending(path: "meta.backup.sqlite")) }
        }
        if let det = detection { try write("detection.json", try enc.encode(await det.stats)) }
        let pi = ProcessInfo.processInfo
        let system: [String: Any] = ["macOS": pi.operatingSystemVersionString, "host": pi.hostName, "cores": pi.activeProcessorCount, "memoryGB": Double(pi.physicalMemory) / 1e9,
                                     "collectorVersion": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "", "build": Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "",
                                     "uptimeSeconds": pi.systemUptime, "interfaces": NetworkInterfaces.list().map { "\($0.name): \($0.addresses.joined(separator: ", "))" }]
        try write("system.json", try JSONSerialization.data(withJSONObject: system, options: [.prettyPrinted, .sortedKeys]))
        // Unified log excerpt (best effort; `log show` can take a while on busy systems).
        let logURL = dir.appending(path: "log-2h.txt")
        let proc = Process(); proc.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        proc.arguments = ["show", "--last", "2h", "--style", "compact", "--predicate", "subsystem BEGINSWITH \"\(Branding.logSubsystemPrefix)\""]
        let out = FileHandle(forWritingAtPath: FileManager.default.createFile(atPath: logURL.path, contents: nil) ? logURL.path : "/dev/null")
        proc.standardOutput = out; proc.standardError = out
        try? proc.run(); proc.waitUntilExit(); try? out?.close()
        if includeTelemetry, let capDir = try? FileManager.default.contentsOfDirectory(at: storeRoot.appending(path: "captures"), includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]),
           let newest = capDir.filter({ $0.pathExtension == "nsraw" }).max(by: { ((try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) < ((try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) }),
           ((try? newest.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0) < 50_000_000 {
            try? FileManager.default.copyItem(at: newest, to: dir.appending(path: newest.lastPathComponent))
        }
        let zip = try Self.zip(dir)
        try? FileManager.default.removeItem(at: dir)
        log.notice("Diagnostics exported to \(zip.path, privacy: .public)")
        return zip.path
    }

    /// Manifest backup (SQLite online backup, consistent even while writing) plus the configuration, zipped.
    func backupStore() async throws -> StorageBackupRequest.Reply {
        guard let store = await storage?.meta else { throw IPCError.rejected("Storage is not open") }
        let stamp = Self.stampFormatter.string(from: Date())
        let dir = storeRoot.appending(path: "backups/netsentry-backup-\(stamp)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let b = try await store.backupMeta()
        try FileManager.default.copyItem(at: b, to: dir.appending(path: "meta.sqlite"))
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(configuration).write(to: dir.appending(path: "collector.json"), options: .atomic)
        try Data("Restore: stop the collector, replace <Store>/meta.sqlite with this file (remove meta.sqlite-wal/-shm), restart. See docs/storage-lifecycle.md.\n".utf8).write(to: dir.appending(path: "README.txt"))
        let zip = try Self.zip(dir)
        try? FileManager.default.removeItem(at: dir)
        let bytes = Int64((try? zip.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        log.notice("Backup written to \(zip.path, privacy: .public) (\(bytes) bytes)")
        return .init(path: zip.path, bytes: bytes)
    }

    private static func zip(_ dir: URL) throws -> URL {
        let zip = dir.appendingPathExtension("zip")
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        p.arguments = ["-c", "-k", "--norsrc", "--noextattr", "--keepParent", dir.path, zip.path]
        try p.run(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw IPCError.rejected("ditto failed with status \(p.terminationStatus)") }
        return zip
    }

    func runListenerTest(kind: ListenerKind, seconds: Int) async -> ListenerTestRequest.Reply {
        let acc = ListenerTestAccumulator(kind: kind)
        let id = UUID()
        testObservers[id] = acc
        try? await Task.sleep(for: .seconds(seconds))
        testObservers.removeValue(forKey: id)
        let listening = await health.snapshot().listeners.contains { $0.kind == kind && $0.state == .listening }
        return acc.result(listening: listening)
    }

    var liveHub: LiveHub { live }
}

/// Bridges Network.framework delegate callbacks (listener queue) into the actor.
final class ListenerBridge: NetworkListenerDelegate, @unchecked Sendable {
    private weak var service: CollectorService?
    init(service: CollectorService) { self.service = service }

    func listener(_ listener: NetworkListener, didChangeState state: ListenerState) {
        let cfg = listener.configuration
        Task { await service?.listenerStateChanged(cfg, state: state) }
    }
    func listener(_ listener: NetworkListener, didReceive datagram: RawDatagram) {
        service?.enqueue(datagram)
    }
    func listener(_ listener: NetworkListener, connectionCountChanged count: Int) {
        let cfg = listener.configuration
        Task { await service?.connectionCountChanged(cfg, count: count) }
    }
}

/// Collects what arrived on a listener during a setup-wizard test window.
final class ListenerTestAccumulator: @unchecked Sendable {
    let kind: ListenerKind
    private let lock = NSLock()
    private var packets: UInt64 = 0
    private var bytes: UInt64 = 0
    private var sources = Set<String>()
    init(kind: ListenerKind) { self.kind = kind }
    private var templates = 0
    private var records: UInt64 = 0
    func record(batch: [RawDatagram], decoded: DecodedBatch) {
        lock.lock(); defer { lock.unlock() }
        for d in batch where d.kind == kind {
            packets += 1; bytes += UInt64(d.payload.count)
            if sources.count < 16 { sources.insert(d.source.description) }
        }
        if kind == .ipfix { templates += decoded.templatesSeen; records += UInt64(decoded.flows.count) }
        else { records += UInt64(decoded.events.count) }
    }
    func result(listening: Bool) -> ListenerTestRequest.Reply {
        lock.lock(); defer { lock.unlock() }
        return .init(kind: kind, listening: listening, packets: packets, bytes: bytes, sources: sources.sorted(),
                     templatesSeen: templates, recordsDecoded: records, errors: [])
    }
}

/// Fan-out of sampled live records to XPC subscribers. Phase 1 publishes raw datagram summaries as
/// zero decoded records; Phase 2 feeds decoded flows/events.
actor LiveHub {
    struct Subscriber { let filter: LiveFilter; let maxPerSecond: Int; let deliver: @Sendable (LiveBatch) -> Void }
    private var subscribers: [UUID: Subscriber] = [:]
    private var pendingFlows: [FlowRecord] = []
    private var pendingEvents: [SyslogEvent] = []
    private var sampledOut = 0
    private var flushTask: Task<Void, Never>?

    func subscribe(filter: LiveFilter, maxPerSecond: Int, deliver: @escaping @Sendable (LiveBatch) -> Void) -> UUID {
        let id = UUID()
        subscribers[id] = Subscriber(filter: filter, maxPerSecond: max(1, min(maxPerSecond, 5_000)), deliver: deliver)
        if flushTask == nil {
            flushTask = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .milliseconds(250))
                    await self?.flush()
                }
            }
        }
        return id
    }

    func unsubscribe(_ id: UUID) {
        subscribers.removeValue(forKey: id)
        if subscribers.isEmpty { flushTask?.cancel(); flushTask = nil }
    }

    func removeAll(matching ids: Set<UUID>) { for id in ids { unsubscribe(id) } }

    func publish(flows: [FlowRecord], events: [SyslogEvent]) {
        guard !subscribers.isEmpty else { return }
        let cap = 2_000
        let room = max(0, cap - pendingFlows.count - pendingEvents.count)
        let take = min(room, flows.count + events.count)
        sampledOut += flows.count + events.count - take
        pendingFlows.append(contentsOf: flows.prefix(min(flows.count, take)))
        pendingEvents.append(contentsOf: events.prefix(max(0, take - flows.count)))
    }

    private func flush() {
        guard !subscribers.isEmpty, !(pendingFlows.isEmpty && pendingEvents.isEmpty && sampledOut == 0) else { return }
        for (id, s) in subscribers {
            let perBatch = max(1, s.maxPerSecond / 4)
            let f = s.filter.flows ? Array(pendingFlows.prefix(perBatch)) : []
            let e = s.filter.events ? Array(pendingEvents.prefix(max(0, perBatch - f.count))) : []
            let out = sampledOut + (pendingFlows.count - f.count) + (pendingEvents.count - e.count)
            s.deliver(LiveBatch(subscriptionID: id, flows: f, events: e, sampledOut: out, generatedAt: .now))
        }
        pendingFlows.removeAll(keepingCapacity: true)
        pendingEvents.removeAll(keepingCapacity: true)
        sampledOut = 0
    }
}
