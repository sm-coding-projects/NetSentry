import Foundation
import NetSentryCore
import NetSentryPersistence
import os

/// Aggregates counters, rates, listener/exporter state, warnings and gaps into HealthSnapshots.
actor HealthMonitor {
    private let log = Log.logger("health", process: "collector")
    let startedAt = Timestamp.now
    private(set) var counters = PipelineCounters()
    private var listeners: [String: ListenerStatus] = [:]
    private var exporters: [String: ExporterStatus] = [:]
    private var warnings: [String: HealthWarning] = [:]
    private var openGaps: [GapKind: CollectionGap] = [:]
    private var queueStatsProvider: (@Sendable () -> [QueueStats])?
    private var asyncQueueStatsProvider: (@Sendable () async -> [QueueStats])?
    private var lastAsyncQueueStats: [QueueStats] = []
    private var storageProvider: (@Sendable () async -> StorageSummary?)?
    private var meta: MetaStore?
    private var demoWorkspace = false

    // Rate window: one sample per second, last 10.
    private struct Sample { let at: UInt64; let counters: PipelineCounters }
    private var samples: [Sample] = []
    private var nextGapID: Int64 = -1

    func attach(meta: MetaStore?, demo: Bool) { self.meta = meta; self.demoWorkspace = demo }
    func setQueueStatsProvider(_ p: @escaping @Sendable () -> [QueueStats]) { queueStatsProvider = p }
    func setAsyncQueueStatsProvider(_ p: @escaping @Sendable () async -> [QueueStats]) { asyncQueueStatsProvider = p }
    private func allQueueStats() async -> [QueueStats] {
        if let asyncQueueStatsProvider { lastAsyncQueueStats = await asyncQueueStatsProvider() }
        return (queueStatsProvider?() ?? []) + lastAsyncQueueStats
    }
    func setStorageProvider(_ p: @escaping @Sendable () async -> StorageSummary?) { storageProvider = p }

    // MARK: Counters

    func record(datagram: RawDatagram) {
        counters.datagramsReceived += 1
        counters.bytesReceived += UInt64(datagram.payload.count)
        let key = "\(datagram.kind.rawValue)-\(datagram.transport.rawValue)-\(datagram.localPort)"
        if var l = listeners[key] {
            l.datagramsReceived += 1
            l.bytesReceived += UInt64(datagram.payload.count)
            l.lastPacketAt = datagram.receivedAt
            l.lastSource = datagram.source.description
            listeners[key] = l
        }
        if let g = openGaps[.exporterSilent] { closeGap(g.kind, at: datagram.receivedAt) }
    }

    func recordReceiveDrops(_ n: UInt64) {
        guard n > 0 else { return }
        counters.receiveQueueDropped += n
        if openGaps[.receiveDrops] == nil {
            openGap(.receiveDrops, reason: "Receive queue full; \(n) datagrams dropped", details: ["dropped": "\(n)"])
        }
    }

    func update(_ body: (inout PipelineCounters) -> Void) { body(&counters) }

    // MARK: Listeners

    func setListener(_ status: ListenerStatus) {
        if var existing = listeners[status.id] {
            existing.state = status.state
            existing.interface = status.interface
            existing.activeConnections = status.activeConnections
            listeners[status.id] = existing
        } else {
            listeners[status.id] = status
        }
        let wid = "listener-\(status.id)"
        if case .failed(let reason) = status.state {
            setWarning(HealthWarning(id: wid, level: .critical, title: "\(status.kind.label) listener failed on \(status.transport.label) \(status.port)",
                                     detail: reason, since: .now))
            openGap(.listenerDown, reason: "\(status.kind.label) \(status.transport.label) \(status.port): \(reason)")
        } else {
            clearWarning(wid)
            if status.state == .listening, listeners.values.allSatisfy({ $0.state == .listening || $0.state == .disabled }) {
                closeGap(.listenerDown)
            }
        }
    }

    func removeListener(id: String) { listeners.removeValue(forKey: id); clearWarning("listener-\(id)") }
    func setConnectionCount(id: String, count: Int) { listeners[id]?.activeConnections = count }

    // MARK: Exporters

    func setExporter(_ status: ExporterStatus) { exporters[status.id] = status }
    func exporter(id: String) -> ExporterStatus? { exporters[id] }

    // MARK: Warnings and gaps

    func setWarning(_ w: HealthWarning) {
        if warnings[w.id] == nil { log.warning("\(w.title, privacy: .public): \(w.detail, privacy: .public)") }
        warnings[w.id] = warnings[w.id].map { var x = $0; x.detail = w.detail; x.level = w.level; return x } ?? w
    }
    func clearWarning(_ id: String) { warnings.removeValue(forKey: id) }

    func openGap(_ kind: GapKind, reason: String, at: Timestamp = .now, details: [String: String] = [:]) {
        guard openGaps[kind] == nil else { return }
        let id: Int64
        if let meta {
            id = (try? meta_openGap(meta, kind, reason, at, details)) ?? nextTempID()
        } else { id = nextTempID() }
        openGaps[kind] = CollectionGap(id: id, start: at, end: nil, kind: kind, reason: reason, details: details)
        log.notice("Collection gap opened: \(kind.rawValue, privacy: .public) — \(reason, privacy: .public)")
    }

    func closeGap(_ kind: GapKind, at: Timestamp = .now) {
        guard let g = openGaps.removeValue(forKey: kind) else { return }
        if let meta, g.id > 0 { Task { try? await meta.closeGap(id: g.id, at: at) } }
        log.notice("Collection gap closed: \(kind.rawValue, privacy: .public)")
    }

    private func nextTempID() -> Int64 { defer { nextGapID -= 1 }; return nextGapID }
    private func meta_openGap(_ meta: MetaStore, _ kind: GapKind, _ reason: String, _ at: Timestamp, _ details: [String: String]) throws -> Int64 {
        // Synchronous bridge is not possible from an actor; persist asynchronously and use a temp id until then.
        let tmp = nextTempID()
        Task { [weak self] in
            if let real = try? await meta.openGap(kind: kind, reason: reason, at: at, details: details) {
                await self?.replaceGapID(kind: kind, tmp: tmp, real: real)
            }
        }
        return tmp
    }
    private func replaceGapID(kind: GapKind, tmp: Int64, real: Int64) {
        if var g = openGaps[kind], g.id == tmp { g.id = real; openGaps[kind] = g }
    }

    // MARK: Sampling / rates

    func tick() async {
        let now = MonotonicClock.continuousNanoseconds
        samples.append(Sample(at: now, counters: counters))
        if samples.count > 11 { samples.removeFirst(samples.count - 11) }
        // Exporter silence: warn when a known exporter has been quiet for 5 minutes while listeners are up.
        let silent = exporters.values.filter { Timestamp.now.microseconds - $0.lastSeen.microseconds > 300_000_000 }
        for e in silent {
            setWarning(HealthWarning(id: "silent-\(e.id)", level: .warning, title: "\(e.kind.label) exporter \(e.key) silent",
                                     detail: "No data for over 5 minutes. Check the gateway export settings and the Mac's address.", since: e.lastSeen))
        }
        for e in exporters.values where !silent.contains(where: { $0.id == e.id }) { clearWarning("silent-\(e.id)") }
        let queues = await allQueueStats()
        for q in queues where q.utilization > 0.8 {
            setWarning(HealthWarning(id: "queue-\(q.name)", level: .warning, title: "Queue \(q.name) at \(Int(q.utilization * 100)) %",
                                     detail: "Downstream stages are falling behind; records may be dropped.", since: .now))
        }
        for q in queues where q.utilization <= 0.5 { clearWarning("queue-\(q.name)") }
        if counters.receiveQueueDropped > 0, openGaps[.receiveDrops] != nil, queues.first(where: { $0.name == "receive" })?.utilization ?? 0 < 0.5 {
            closeGap(.receiveDrops)
        }
    }

    private var rates: PipelineRates {
        var r = PipelineRates()
        guard let first = samples.first, let last = samples.last, last.at > first.at else { return r }
        let seconds = Double(last.at - first.at) / 1e9
        r.windowSeconds = seconds
        r.datagramsPerSecond = Double(last.counters.datagramsReceived - first.counters.datagramsReceived) / seconds
        r.flowsPerSecond = Double(last.counters.flowsDecoded - first.counters.flowsDecoded) / seconds
        r.eventsPerSecond = Double(last.counters.eventsDecoded - first.counters.eventsDecoded) / seconds
        r.bytesPerSecond = Double(last.counters.bytesReceived - first.counters.bytesReceived) / seconds
        let f0 = first.counters.malformed + first.counters.parserFailures + first.counters.storageWriteFailures + first.counters.receiveQueueDropped
        let f1 = last.counters.malformed + last.counters.parserFailures + last.counters.storageWriteFailures + last.counters.receiveQueueDropped
        r.failuresPerSecond = Double(f1 - f0) / seconds
        return r
    }

    func snapshot() async -> HealthSnapshot {
        HealthSnapshot(generatedAt: .now, collectorVersion: Branding.version, collectorBuild: Branding.build, startedAt: startedAt,
                       pid: ProcessInfo.processInfo.processIdentifier,
                       listeners: listeners.values.sorted { $0.id < $1.id },
                       exporters: exporters.values.sorted { $0.id < $1.id },
                       counters: counters, rates: rates, queues: await allQueueStats(),
                       openGaps: openGaps.values.sorted { $0.start < $1.start },
                       warnings: warnings.values.sorted { $0.since < $1.since },
                       storage: await storageProvider?(), demoWorkspace: demoWorkspace)
    }
}
