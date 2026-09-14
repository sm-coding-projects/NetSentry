import DuckDB
import Foundation
import NetSentryCore
import os

/// Usage broken down the way the budget allocation is defined.
public struct StorageUsage: Sendable, Hashable, Codable {
    public var flows: Int64 = 0        // finalized flow segments
    public var events: Int64 = 0       // finalized event segments minus raw columns
    public var raw: Int64 = 0          // raw syslog columns inside event segments + diagnostic captures
    public var metadata: Int64 = 0     // meta.sqlite (+wal), backups
    public var other: Int64 = 0        // tmp, exports, geoip, anything else under the root
    public var total: Int64 { flows + events + raw + metadata + other }
    public init() {}
    public var byCategory: [String: Int64] { ["flows": flows, "events": events, "raw": raw, "metadata": metadata, "other": other] }
}

/// What a retention pass (or a budget change) would remove.
public struct RetentionPlan: Sendable, Hashable, Codable {
    public struct Step: Sendable, Hashable, Codable {
        public var stage: Int
        public var description: String
        public var bytesFreed: Int64
        public var segments: Int
        public var oldestSurvivingFlow: NetSentryCore.Timestamp?
        public var oldestSurvivingEvent: NetSentryCore.Timestamp?
    }
    public var budgetBytes: Int64
    public var usageBefore: Int64
    public var usageAfter: Int64
    public var steps: [Step] = []
    public var removesRecentData: Bool = false
    public init(budgetBytes: Int64, usageBefore: Int64, usageAfter: Int64) { self.budgetBytes = budgetBytes; self.usageBefore = usageBefore; self.usageAfter = usageAfter }
}

public enum StorageError: Error, LocalizedError {
    case diskPressure(freeBytes: Int64, thresholdBytes: Int64)
    case notOpen
    public var errorDescription: String? {
        switch self {
        case .diskPressure(let f, let t): "Free space (\(f / 1_000_000) MB) is below the safety threshold (\(t / 1_000_000) MB)."
        case .notOpen: "Storage is not open."
        }
    }
}

/// Owns the storage root: staging, flushing, usage accounting, budget and disk-safety enforcement,
/// retention stages, compaction and startup recovery. One instance per collector process.
public actor StorageManager {
    public struct Policy: Sendable {
        public var budgetBytes: Int64
        public var allocation: BudgetAllocation
        public var safetyThreshold: SafetyThreshold
        public var rawRetentionDays: Int
        public var compactAfterDays: Int
        public var flushInterval: Duration = .seconds(60)
        public var origin: Origin = .live
        public init(budgetBytes: Int64, allocation: BudgetAllocation = BudgetAllocation(), safetyThreshold: SafetyThreshold = SafetyThreshold(),
                    rawRetentionDays: Int = 7, compactAfterDays: Int = 30) {
            self.budgetBytes = budgetBytes; self.allocation = allocation; self.safetyThreshold = safetyThreshold
            self.rawRetentionDays = rawRetentionDays; self.compactAfterDays = compactAfterDays
        }
        public init(configuration c: CollectorConfiguration) {
            self.init(budgetBytes: c.budgetBytes, allocation: c.allocation, safetyThreshold: c.safetyThreshold, rawRetentionDays: c.rawRetentionDays, compactAfterDays: c.compactAfterDays)
            origin = c.demoWorkspace ? .simulated : .live
        }
    }

    public nonisolated let root: URL
    public nonisolated let meta: MetaStore
    public nonisolated let engine: DuckEngine
    public private(set) var policy: Policy
    private let writer: SegmentWriter
    private let log = Log.logger("storage", process: "collector")
    private var lastFlush = NetSentryCore.Timestamp.now
    private var exporterIDs: [ExporterKey: Int32] = [:]
    public private(set) var ingestionPaused = false
    public private(set) var pauseReason: String?
    public private(set) var compactionInProgress = false
    public private(set) var integrityIssues: [String] = []
    public private(set) var lastUsage = StorageUsage()
    public private(set) var recoveryReport: [String] = []
    private var pendingWhilePaused: (flows: [FlowRecord], events: [SyslogEvent]) = ([], [])
    private static let pausedBufferLimit = 100_000

    public init(root: URL, policy: Policy, engine: DuckEngine? = nil) async throws {
        self.root = root
        self.policy = policy
        meta = try MetaStore(root: root)
        self.engine = try engine ?? DuckEngine(memoryLimit: "512MB", threads: 2, temporaryDirectory: root.appending(path: "tmp"))
        writer = try await SegmentWriter(root: root, engine: self.engine, meta: meta)
        try await recover()
        lastUsage = try await measureUsage()
        do { try await checkDiskSafety() } catch StorageError.diskPressure { /* paused; reported through `ingestionPaused` */ }
    }

    public func update(policy: Policy) { self.policy = policy }

    // MARK: - Ingest

    /// Stages records; assigns ids in place. Flushes when the writer reaches its row limit.
    public func ingest(flows: inout [FlowRecord], events: inout [SyslogEvent], exporters: [ExporterKey: Int32]) async throws {
        for (k, v) in exporters { exporterIDs[k] = v }
        if ingestionPaused {
            let room = Self.pausedBufferLimit - pendingWhilePaused.flows.count - pendingWhilePaused.events.count
            if room > 0 {
                pendingWhilePaused.flows.append(contentsOf: flows.prefix(room))
                pendingWhilePaused.events.append(contentsOf: events.prefix(max(0, room - flows.count)))
            }
            return
        }
        let due = try await writer.stage(flows: &flows, events: &events, exporterIDs: exporterIDs)
        for kind in due { try await flushKind(kind) }
    }

    /// Called every second by the collector; flushes on the interval and runs housekeeping.
    public func tick(now: NetSentryCore.Timestamp = .now) async {
        if now.microseconds - lastFlush.microseconds >= policy.flushInterval.microsecondsValue {
            await flushAll(now: now)
        }
    }

    public func flushAll(now: NetSentryCore.Timestamp = .now) async {
        lastFlush = now
        for kind in SegmentKind.allCases {
            do { try await flushKind(kind, now: now) } catch { log.error("flush \(kind.rawValue, privacy: .public) failed: \(error.localizedDescription, privacy: .public)") }
        }
        if let usage = try? await measureUsage() { lastUsage = usage }
        try? await checkDiskSafety()
        if lastUsage.total > policy.budgetBytes { await enforceBudget() }
    }

    private func flushKind(_ kind: SegmentKind, now: NetSentryCore.Timestamp = .now) async throws {
        try await checkDiskSafety()
        _ = try await writer.flush(kind, origin: policy.origin, now: now)
    }

    public var stagedRecords: Int { get async { await writer.stagedTotal } }
    public var writeFailures: Int { get async { await writer.writeFailures } }

    // MARK: - Usage and safety

    public func measureUsage() async throws -> StorageUsage {
        var u = StorageUsage()
        let seg = try await meta.segmentUsage()
        u.flows = seg.flows
        u.raw = seg.raw
        u.events = max(0, seg.events - seg.raw)
        let fm = FileManager.default
        for name in ["meta.sqlite", "meta.sqlite-wal", "meta.sqlite-shm"] { u.metadata += Self.fileSize(root.appending(path: name)) }
        u.metadata += Self.directorySize(root.appending(path: "backups"))
        u.raw += Self.directorySize(root.appending(path: "captures"))
        for sub in ["tmp", "exports", "geoip"] { u.other += Self.directorySize(root.appending(path: sub)) }
        _ = fm
        return u
    }

    public func volumeInfo() -> (free: Int64, size: Int64) {
        let attrs = try? FileManager.default.attributesOfFileSystem(forPath: root.path)
        return ((attrs?[.systemFreeSize] as? Int64) ?? 0, (attrs?[.systemSize] as? Int64) ?? 0)
    }

    public var safetyThresholdBytes: Int64 { policy.safetyThreshold.bytes(forVolumeSize: volumeInfo().size) }

    /// Pauses ingestion when the volume is below the safety threshold; resumes with 1 GB hysteresis.
    private func checkDiskSafety() async throws {
        let (free, _) = volumeInfo()
        let threshold = safetyThresholdBytes
        if !ingestionPaused, free < threshold {
            ingestionPaused = true
            pauseReason = "Free space \(free / 1_000_000_000) GB is below the safety threshold of \(threshold / 1_000_000_000) GB"
            log.error("Ingestion paused: \(self.pauseReason ?? "", privacy: .public)")
            await enforceBudget()
            throw StorageError.diskPressure(freeBytes: free, thresholdBytes: threshold)
        }
        if ingestionPaused, free > threshold + 1_000_000_000 {
            ingestionPaused = false
            pauseReason = nil
            log.notice("Ingestion resumed; free space recovered")
            var f = pendingWhilePaused.flows, e = pendingWhilePaused.events
            pendingWhilePaused = ([], [])
            if !f.isEmpty || !e.isEmpty { _ = try? await writer.stage(flows: &f, events: &e, exporterIDs: exporterIDs) }
        }
    }

    // MARK: - Retention

    /// Computes what a retention pass would do for `budget` without changing anything.
    public func plan(budget: Int64, now: NetSentryCore.Timestamp = .now) async throws -> RetentionPlan {
        let usage = try await measureUsage()
        var plan = RetentionPlan(budgetBytes: budget, usageBefore: usage.total, usageAfter: usage.total)
        var remaining = usage.total
        let target = Int64(Double(budget) * 0.97)
        guard remaining > target else { return plan }
        // Stage 1: diagnostic captures.
        let captures = Self.directorySize(root.appending(path: "captures"))
        if captures > 0 { remaining -= captures; plan.steps.append(.init(stage: 1, description: "Delete diagnostic packet captures", bytesFreed: captures, segments: 0, oldestSurvivingFlow: nil, oldestSurvivingEvent: nil)) }
        if remaining <= target { plan.usageAfter = remaining; return plan }
        // Stage 2: raw syslog columns older than rawRetentionDays.
        let rawCutoff = NetSentryCore.Timestamp(microseconds: now.microseconds - Int64(policy.rawRetentionDays) * 86_400_000_000)
        let eventSegs = try await meta.segments(kind: .events, to: rawCutoff)
        let rawFreed = eventSegs.reduce(0) { $0 + $1.rawBytes }
        if rawFreed > 0 { remaining -= rawFreed; plan.steps.append(.init(stage: 2, description: "Remove raw copies of syslog messages older than \(policy.rawRetentionDays) days", bytesFreed: rawFreed, segments: eventSegs.count, oldestSurvivingFlow: nil, oldestSurvivingEvent: nil)) }
        if remaining <= target { plan.usageAfter = remaining; return plan }
        // Stage 3: aggregate old flow segments (estimate 80 % saving).
        let compactCutoff = NetSentryCore.Timestamp(microseconds: now.microseconds - Int64(policy.compactAfterDays) * 86_400_000_000)
        let compactable = try await meta.segments(kind: .flows, to: compactCutoff).filter { !$0.compacted }
        let compactFreed = Int64(Double(compactable.reduce(0) { $0 + $1.bytes }) * 0.8)
        if compactFreed > 0 { remaining -= compactFreed; plan.steps.append(.init(stage: 3, description: "Aggregate flow records older than \(policy.compactAfterDays) days into 5-minute summaries", bytesFreed: compactFreed, segments: compactable.count, oldestSurvivingFlow: nil, oldestSurvivingEvent: nil)) }
        if remaining <= target { plan.usageAfter = remaining; return plan }
        // Stage 5: delete oldest detailed segments, weighted by category overshoot.
        var flows = try await meta.segments(kind: .flows)
        var events = try await meta.segments(kind: .events)
        var freed: Int64 = 0, count = 0
        let flowBudget = Int64(Double(budget) * policy.allocation.flows), eventBudget = Int64(Double(budget) * (policy.allocation.events + policy.allocation.raw))
        var flowBytes = usage.flows, eventBytes = usage.events + usage.raw
        while remaining > target, !(flows.isEmpty && events.isEmpty) {
            let flowOver = Double(flowBytes) / Double(max(flowBudget, 1)), eventOver = Double(eventBytes) / Double(max(eventBudget, 1))
            let victim: SegmentRecord
            if !flows.isEmpty, events.isEmpty || flowOver >= eventOver { victim = flows.removeFirst(); flowBytes -= victim.bytes } else { victim = events.removeFirst(); eventBytes -= victim.bytes }
            remaining -= victim.bytes; freed += victim.bytes; count += 1
            if now.microseconds - victim.end.microseconds < 86_400_000_000 { plan.removesRecentData = true }
        }
        plan.steps.append(.init(stage: 5, description: "Delete the oldest detailed flow and event segments", bytesFreed: freed, segments: count,
                                oldestSurvivingFlow: flows.first?.start, oldestSurvivingEvent: events.first?.start))
        plan.usageAfter = remaining
        return plan
    }

    /// Runs the retention stages until usage is within 97 % of the budget. Rollups, alerts and annotations are never touched.
    public func enforceBudget(now: NetSentryCore.Timestamp = .now) async {
        let budget = policy.budgetBytes
        let target = Int64(Double(budget) * 0.97)
        func over() async -> Bool { (try? await measureUsage()).map { $0.total > target } ?? false }
        guard await over() else { return }
        log.notice("Storage over budget; running retention stages")
        // 1. captures
        try? FileManager.default.removeItem(at: root.appending(path: "captures"))
        guard await over() else { return }
        // 2. raw stripping
        let rawCutoff = NetSentryCore.Timestamp(microseconds: now.microseconds - Int64(policy.rawRetentionDays) * 86_400_000_000)
        if let segs = try? await meta.segments(kind: .events, to: rawCutoff) {
            for s in segs where s.rawBytes > 0 {
                do { try await stripRaw(s) } catch { log.error("raw strip failed for \(s.path, privacy: .public): \(error.localizedDescription, privacy: .public)") }
                if !(await over()) { return }
            }
        }
        // 3. aggregate old flows
        let compactCutoff = NetSentryCore.Timestamp(microseconds: now.microseconds - Int64(policy.compactAfterDays) * 86_400_000_000)
        if let segs = try? await meta.segments(kind: .flows, to: compactCutoff) {
            for s in segs where !s.compacted {
                do { try await aggregate(s) } catch { log.error("aggregation failed for \(s.path, privacy: .public): \(error.localizedDescription, privacy: .public)") }
                if !(await over()) { return }
            }
        }
        // 5. delete oldest detailed segments (rollups in SQLite are untouched)
        guard var flows = try? await meta.segments(kind: .flows), var events = try? await meta.segments(kind: .events) else { return }
        var usage = (try? await measureUsage()) ?? StorageUsage()
        let flowBudget = Int64(Double(budget) * policy.allocation.flows), eventBudget = Int64(Double(budget) * (policy.allocation.events + policy.allocation.raw))
        while usage.total > target, !(flows.isEmpty && events.isEmpty) {
            let flowOver = Double(usage.flows) / Double(max(flowBudget, 1)), eventOver = Double(usage.events + usage.raw) / Double(max(eventBudget, 1))
            let victim = (!flows.isEmpty && (events.isEmpty || flowOver >= eventOver)) ? flows.removeFirst() : events.removeFirst()
            await deleteSegment(victim)
            usage = (try? await measureUsage()) ?? usage
        }
    }

    private func deleteSegment(_ s: SegmentRecord) async {
        do {
            try await meta.deleteSegments(ids: [s.id])
            try? FileManager.default.removeItem(at: root.appending(path: s.path))
            log.notice("Deleted segment \(s.path, privacy: .public) (\(s.bytes) bytes)")
        } catch { log.error("delete failed for \(s.path, privacy: .public): \(error.localizedDescription, privacy: .public)") }
    }

    /// Rewrites an event segment without its raw columns (stage 2).
    public func stripRaw(_ s: SegmentRecord) async throws {
        try await rewrite(s, select: "SELECT * REPLACE (NULL AS raw, NULL AS raw_bytes) FROM read_parquet(\(DuckEngine.literal(root.appending(path: s.path).path)))",
                          tier: s.tier, compacted: s.compacted)
    }

    /// Rewrites a flow segment as 5-minute aggregates per (src, dst, dst_port, protocol, direction) (stage 3).
    public func aggregate(_ s: SegmentRecord) async throws {
        let path = DuckEngine.literal(root.appending(path: s.path).path)
        let cols = SegmentSchema.flowColumns.map(\.0)
        let grouped: Set<String> = ["origin", "exporter_id", "exporter_addr", "observation_domain_id", "ip_version", "src_ip", "dst_ip", "src_v4", "dst_v4", "dst_port", "protocol",
                                    "direction", "src_internal", "dst_internal", "src_client_id", "dst_client_id", "src_country", "dst_country", "src_asn", "dst_asn", "dst_org", "service",
                                    "enrichment_version", "schema_version"]
        let selects = cols.map { c -> String in
            switch c {
            case "flow_id": return "MIN(flow_id) AS flow_id"
            case "start_time": return "(start_time // 300000000) * 300000000 AS start_time"
            case "end_time": return "MAX(end_time) AS end_time"
            case "packets", "octets", "rev_packets", "rev_octets": return "SUM(\(c))::UBIGINT AS \(c)"
            case "flow_count": return "SUM(flow_count)::UINTEGER AS flow_count"
            case "tcp_flags": return "BIT_OR(tcp_flags)::USMALLINT AS tcp_flags"
            case "src_port": return "0::USMALLINT AS src_port"
            case _ where grouped.contains(c): return c
            default: return "ANY_VALUE(\(c)) AS \(c)"
            }
        }
        let groupBy = (["(start_time // 300000000) * 300000000"] + cols.filter { grouped.contains($0) }).joined(separator: ", ")
        try await rewrite(s, select: "SELECT \(selects.joined(separator: ", ")) FROM read_parquet(\(path)) GROUP BY \(groupBy) ORDER BY start_time, src_ip", tier: .day, compacted: true)
    }

    private func rewrite(_ s: SegmentRecord, select: String, tier: SegmentTier, compacted: Bool) async throws {
        compactionInProgress = true
        defer { compactionInProgress = false }
        try await meta.setSegmentState(s.id, .compacting)
        let final = root.appending(path: s.path)
        let tmp = root.appending(path: "tmp/\(final.lastPathComponent).rewrite.tmp")
        try FileManager.default.createDirectory(at: root.appending(path: "tmp"), withIntermediateDirectories: true)
        do {
            try engine.execute("COPY (\(select)) TO \(DuckEngine.literal(tmp.path)) (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 65536)")
            let rows = try engine.scalarInt64("SELECT COUNT(*) FROM read_parquet(\(DuckEngine.literal(tmp.path)))") ?? 0
            let rawBytes = s.kind == .events ? (try engine.scalarInt64("SELECT COALESCE(SUM(total_compressed_size), 0)::BIGINT FROM parquet_metadata(\(DuckEngine.literal(tmp.path))) WHERE path_in_schema IN ('raw', 'raw_bytes')") ?? 0) : 0
            try SegmentWriter.fsync(tmp)
            _ = try FileManager.default.replaceItemAt(final, withItemAt: tmp)
            chmod(final.path, 0o600)
            let size = (try FileManager.default.attributesOfItem(atPath: final.path)[.size] as? Int64) ?? 0
            try await meta.updateSegmentAfterRewrite(s.id, path: s.path, bytes: size, rawBytes: rawBytes, rowCount: rows, sha256: try SegmentWriter.sha256(final), compacted: compacted, tier: tier)
            log.notice("Rewrote \(s.path, privacy: .public): \(s.bytes) → \(size) bytes, \(rows) rows")
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            try? await meta.setSegmentState(s.id, .finalized)
            throw error
        }
    }

    // MARK: - Compaction (minute → hour → day)

    /// Merges minute segments of completed hours into one hour segment per kind; then hours into days.
    public func compact(now: NetSentryCore.Timestamp = .now) async {
        compactionInProgress = true
        defer { compactionInProgress = false }
        for kind in SegmentKind.allCases {
            await merge(kind: kind, from: .minute, into: .hour, bucketMicros: 3_600_000_000, graceMicros: 300_000_000, now: now)
            await merge(kind: kind, from: .hour, into: .day, bucketMicros: 86_400_000_000, graceMicros: 3_600_000_000, now: now)
        }
        await buildDayTier(now: now)
    }

    /// Day rollups and daily summaries for every completed UTC day that has hour rollups but no summary yet.
    public func buildDayTier(now: NetSentryCore.Timestamp = .now) async {
        do {
            let pending = try await meta.daysNeedingSummary(origin: policy.origin, now: now)
            log.notice("Day tier check: \(pending.count) day(s) pending (origin \(self.policy.origin.rawValue))")
            for day in pending {
                let rows = try await meta.buildDayRollups(day: day, origin: policy.origin)
                _ = try await meta.buildDailySummary(day: day, origin: policy.origin)
                log.notice("Day tier built for \(day.date.formatted(date: .abbreviated, time: .omitted), privacy: .public): \(rows) rows")
            }
        } catch { log.error("day tier failed: \(error.localizedDescription, privacy: .public)") }
    }

    private func merge(kind: SegmentKind, from: SegmentTier, into: SegmentTier, bucketMicros: Int64, graceMicros: Int64, now: NetSentryCore.Timestamp) async {
        guard let segs = try? await meta.segments(kind: kind).filter({ $0.tier == from && !$0.compacted }) else { return }
        let groups = Dictionary(grouping: segs) { $0.start.microseconds / bucketMicros }
        for (bucket, members) in groups.sorted(by: { $0.key < $1.key }) where members.count >= 2 {
            let bucketEnd = (bucket + 1) * bucketMicros
            guard now.microseconds > bucketEnd + graceMicros else { continue }
            do { try await mergeGroup(kind: kind, members: members.sorted { $0.start < $1.start }, tier: into, bucketStart: NetSentryCore.Timestamp(microseconds: bucket * bucketMicros)) }
            catch { log.error("compaction of \(members.count) \(kind.rawValue, privacy: .public) segments failed: \(error.localizedDescription, privacy: .public)") }
        }
    }

    private func mergeGroup(kind: SegmentKind, members: [SegmentRecord], tier: SegmentTier, bucketStart: NetSentryCore.Timestamp) async throws {
        let paths = members.map { root.appending(path: $0.path).path }
        let seq = try await meta.nextSegmentSequence()
        let relative = SegmentWriter.relativePath(kind: kind, tier: tier, start: bucketStart, sequence: seq)
        let final = root.appending(path: relative)
        let tmp = root.appending(path: "tmp/\(final.lastPathComponent).tmp")
        try FileManager.default.createDirectory(at: final.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let order = kind == .flows ? "start_time, src_ip" : "received_at"
        try engine.execute("COPY (SELECT * FROM read_parquet(\(DuckEngine.pathList(paths))) ORDER BY \(order)) TO \(DuckEngine.literal(tmp.path)) (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 65536)")
        let rows = try engine.scalarInt64("SELECT COUNT(*) FROM read_parquet(\(DuckEngine.literal(tmp.path)))") ?? 0
        let expected = members.reduce(0) { $0 + $1.rowCount }
        guard rows == expected else { try? FileManager.default.removeItem(at: tmp); throw StorageError.notOpen }
        let rawBytes = kind == .events ? (try engine.scalarInt64("SELECT COALESCE(SUM(total_compressed_size), 0)::BIGINT FROM parquet_metadata(\(DuckEngine.literal(tmp.path))) WHERE path_in_schema IN ('raw', 'raw_bytes')") ?? 0) : 0
        try SegmentWriter.fsync(tmp)
        _ = try FileManager.default.replaceItemAt(final, withItemAt: tmp)
        chmod(final.path, 0o600)
        let size = (try FileManager.default.attributesOfItem(atPath: final.path)[.size] as? Int64) ?? 0
        let record = SegmentRecord(kind: kind, tier: tier, start: members.first!.start, end: members.map(\.end).max()!, path: relative, rowCount: rows, bytes: size, rawBytes: rawBytes,
                                   state: .finalized, schemaVersion: members.first!.schemaVersion, enrichmentVersion: members.map(\.enrichmentVersion).min() ?? 1,
                                   sha256: try SegmentWriter.sha256(final), createdAt: .now, finalizedAt: .now, origin: members.first!.origin)
        var stats: [SegmentColumnStats] = []
        for m in members { for st in try await meta.segmentStats(id: m.id) {
            if let i = stats.firstIndex(where: { $0.column == st.column }) {
                stats[i].min = [stats[i].min, st.min].compactMap { $0 }.min(); stats[i].max = [stats[i].max, st.max].compactMap { $0 }.max()
            } else { stats.append(st) }
        } }
        _ = try await meta.insertSegment(record, stats: stats)
        try await meta.deleteSegments(ids: members.map(\.id))
        for m in members { try? FileManager.default.removeItem(at: root.appending(path: m.path)) }
        log.notice("Compacted \(members.count) \(kind.rawValue, privacy: .public) segments into \(relative, privacy: .public) (\(rows) rows, \(size) bytes)")
    }

    // MARK: - Recovery and verification

    /// Startup: remove temp files, reconcile manifest ↔ filesystem, verify the newest segments, close stale gaps.
    private func recover() async throws {
        var report: [String] = []
        let fm = FileManager.default
        let tmp = root.appending(path: "tmp")
        if let items = try? fm.contentsOfDirectory(at: tmp, includingPropertiesForKeys: nil) {
            for u in items where u.pathExtension == "tmp" || u.lastPathComponent.hasSuffix(".tmp") {
                try? fm.removeItem(at: u); report.append("Removed interrupted write \(u.lastPathComponent)")
            }
        }
        try await meta.purgeDeletedSegments()
        let manifest = try await meta.allSegments()
        var known = Set<String>()
        for s in manifest where s.state != .deleted {
            known.insert(s.path)
            let exists = fm.fileExists(atPath: root.appending(path: s.path).path)
            if !exists, s.state != .missing { try await meta.setSegmentState(s.id, .missing); report.append("Segment missing on disk: \(s.path)") }
            if exists, s.state == .compacting { try await meta.setSegmentState(s.id, .finalized); report.append("Reverted interrupted rewrite of \(s.path)") }
            if exists, s.state == .missing { try await meta.setSegmentState(s.id, .finalized); report.append("Segment reappeared: \(s.path)") }
        }
        for kind in SegmentKind.allCases {
            let dir = root.appending(path: kind.rawValue)
            if let e = fm.enumerator(at: dir, includingPropertiesForKeys: nil) {
                while let u = e.nextObject() as? URL {
                    guard u.pathExtension == "parquet" else { continue }
                    let rel = u.path.replacingOccurrences(of: root.path + "/", with: "")
                    if !known.contains(rel) {
                        let q = root.appending(path: "tmp/orphan-\(u.lastPathComponent)")
                        try? fm.moveItem(at: u, to: q); report.append("Quarantined orphan file \(rel)")
                    }
                }
            }
        }
        // Verify the newest 3 segments per kind.
        for kind in SegmentKind.allCases {
            let newest = (try? await meta.segments(kind: kind))?.suffix(3) ?? []
            for s in newest {
                let path = DuckEngine.literal(root.appending(path: s.path).path)
                var rows: Int64?
                var lastError = "unreadable"
                for _ in 0..<2 {   // one retry: DuckDB can fail transiently while the file's directory entry settles
                    do { rows = try engine.scalarInt64("SELECT COUNT(*) FROM read_parquet(\(path))"); break } catch { lastError = error.localizedDescription }
                }
                if rows != s.rowCount {
                    try? await meta.setSegmentState(s.id, .corrupt)
                    report.append("Segment failed verification: \(s.path) (file \(rows.map(String.init) ?? lastError), manifest \(s.rowCount))")
                }
            }
        }
        integrityIssues = report.filter { $0.hasPrefix("Segment") }
        recoveryReport = report
        if !report.isEmpty { log.notice("Recovery: \(report.joined(separator: "; "), privacy: .public)") }
    }

    /// Full verification of the given (or all) segments: file present, readable, row count and checksum match.
    /// Full verification of the given (or all) segments, including ones previously marked missing or corrupt:
    /// a segment that passes again is restored to `finalized` (self-healing after transient read failures).
    public func verify(segmentIDs: [Int64]? = nil) async -> [String] {
        var issues: [String] = []
        let segs = (try? await meta.segments(states: [.finalized, .compacting, .missing, .corrupt])) ?? []
        for s in segs where segmentIDs == nil || segmentIDs!.contains(s.id) {
            let url = root.appending(path: s.path)
            guard FileManager.default.fileExists(atPath: url.path) else { issues.append("\(s.path): missing"); try? await meta.setSegmentState(s.id, .missing); continue }
            if let sha = s.sha256, (try? SegmentWriter.sha256(url)) != sha { issues.append("\(s.path): checksum mismatch"); try? await meta.setSegmentState(s.id, .corrupt); continue }
            let rows = try? engine.scalarInt64("SELECT COUNT(*) FROM read_parquet(\(DuckEngine.literal(url.path)))")
            if let rows, rows != s.rowCount, s.sha256 != nil {
                // The file is intact (checksum verified above); only the manifest count drifted. Repair it.
                try? await meta.setSegmentRowCount(s.id, rowCount: rows)
                log.notice("Repaired manifest row count for \(s.path, privacy: .public): \(s.rowCount) → \(rows)")
                continue
            }
            if rows != s.rowCount { issues.append("\(s.path): row count mismatch (file \(rows.map(String.init) ?? "unreadable"), manifest \(s.rowCount))"); try? await meta.setSegmentState(s.id, .corrupt); continue }
            if s.state != .finalized {
                try? await meta.setSegmentState(s.id, .finalized)
                log.notice("Segment \(s.path, privacy: .public) verified and restored to finalized")
            }
        }
        integrityIssues = issues
        return issues
    }

    // MARK: - Summary

    public func summary() async -> StorageSummary {
        let usage = lastUsage
        let (free, _) = volumeInfo()
        let seg = try? await meta.segmentUsage()
        var s = StorageSummary(root: root.path, budgetBytes: policy.budgetBytes, usedBytes: usage.total, usedByCategory: usage.byCategory,
                               freeBytesOnVolume: free, safetyThresholdBytes: safetyThresholdBytes, oldestRecord: seg?.oldest, newestRecord: seg?.newest,
                               estimatedRetentionDays: nil, ingestionPaused: ingestionPaused, segmentCount: seg?.count ?? 0,
                               integrityIssues: integrityIssues.count, compactionInProgress: compactionInProgress)
        if let seg, let oldest = seg.oldest, let newest = seg.newest, newest > oldest, usage.flows + usage.events > 0 {
            let spanDays = Double(newest.microseconds - oldest.microseconds) / 86_400_000_000
            let perDay = Double(usage.flows + usage.events + usage.raw) / max(spanDays, 1.0 / 24)
            let detailedBudget = Double(policy.budgetBytes) * (policy.allocation.flows + policy.allocation.events + policy.allocation.raw)
            s.estimatedRetentionDays = perDay > 0 ? detailedBudget / perDay : nil
        }
        return s
    }

    public func closeGracefully() async {
        await flushAll()
        await meta.checkpoint()
    }

    // MARK: - Helpers

    static func fileSize(_ url: URL) -> Int64 { (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0 }
    static func directorySize(_ url: URL) -> Int64 {
        var total: Int64 = 0
        guard let e = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.totalFileAllocatedSizeKey], options: [.skipsHiddenFiles]) else { return 0 }
        while let u = e.nextObject() as? URL { total += Int64((try? u.resourceValues(forKeys: [.totalFileAllocatedSizeKey]).totalFileAllocatedSize) ?? 0) }
        return total
    }
}
