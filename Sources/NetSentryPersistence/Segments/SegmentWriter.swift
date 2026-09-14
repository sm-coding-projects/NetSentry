import CryptoKit
import DuckDB
import Foundation
import NetSentryCore
import os

/// Accumulates normalized records in DuckDB staging tables and writes them as immutable Parquet
/// segments with atomic finalization (tmp file → fsync → rename → manifest row in one transaction).
public actor SegmentWriter {
    public struct Limits: Sendable {
        public var maxStagedRows = 200_000          // flush early when reached
        public var rowGroupSize = 65_536
        public init() {}
    }

    public let root: URL
    private let engine: DuckEngine
    private let meta: MetaStore
    private let limits: Limits
    private let log = Log.logger("segments", process: "collector")
    private var appenders: [SegmentKind: Appender] = [:]
    private var staged: [SegmentKind: Int] = [.flows: 0, .events: 0]
    private var stagedRange: [SegmentKind: (NetSentryCore.Timestamp, NetSentryCore.Timestamp)] = [:]
    private var nextID: Int64
    private var sequence: Int64
    public private(set) var writeFailures = 0

    public init(root: URL, engine: DuckEngine, meta: MetaStore) async throws {
        self.root = root
        self.engine = engine
        self.meta = meta
        self.limits = Limits()
        for kind in SegmentKind.allCases { try engine.execute(SegmentSchema.createTableSQL(kind, name: "\(kind.rawValue)_stage")) }
        sequence = try await meta.nextSegmentSequence()
        nextID = sequence << 32
    }

    public func stagedCount(_ kind: SegmentKind) -> Int { staged[kind] ?? 0 }
    public var stagedTotal: Int { staged.values.reduce(0, +) }

    /// Appends records; ids are assigned here. Returns kinds that reached the row limit and should be flushed.
    public func stage(flows: inout [FlowRecord], events: inout [SyslogEvent], exporterIDs: [ExporterKey: Int32]) throws -> Set<SegmentKind> {
        var due: Set<SegmentKind> = []
        if !flows.isEmpty {
            let a = try appender(.flows)
            for i in flows.indices {
                nextID += 1
                flows[i].id = nextID
                try SegmentSchema.append(flows[i], exporterID: exporterIDs[flows[i].exporter] ?? 0, to: a)
                track(.flows, flows[i].startTime, flows[i].endTime)
                staged[.flows, default: 0] += 1
            }
            if staged[.flows]! >= limits.maxStagedRows { due.insert(.flows) }
        }
        if !events.isEmpty {
            let a = try appender(.events)
            for i in events.indices {
                nextID += 1
                events[i].id = nextID
                try SegmentSchema.append(events[i], to: a)
                track(.events, events[i].receivedAt, events[i].receivedAt)
                staged[.events, default: 0] += 1
            }
            if staged[.events]! >= limits.maxStagedRows { due.insert(.events) }
        }
        return due
    }

    private func track(_ kind: SegmentKind, _ start: NetSentryCore.Timestamp, _ end: NetSentryCore.Timestamp) {
        if let r = stagedRange[kind] { stagedRange[kind] = (min(r.0, start), max(r.1, end)) } else { stagedRange[kind] = (start, end) }
    }

    private func appender(_ kind: SegmentKind) throws -> Appender {
        if let a = appenders[kind] { return a }
        let a = try Appender(connection: engine.connection, table: "\(kind.rawValue)_stage")
        appenders[kind] = a
        return a
    }

    /// Writes the staged rows of `kind` as a minute-tier segment. Returns nil when nothing was staged.
    @discardableResult
    public func flush(_ kind: SegmentKind, origin: Origin = .live, now: NetSentryCore.Timestamp = .now) async throws -> SegmentRecord? {
        guard let stagedCount = staged[kind], stagedCount > 0 else { return nil }
        if let a = appenders[kind] { try a.flush() }
        appenders[kind] = nil
        let table = "\(kind.rawValue)_stage"
        // The table is authoritative for the manifest row count (appends that failed part-way are still rows).
        let count = Int(try engine.scalarInt64("SELECT COUNT(*) FROM \(table)") ?? Int64(stagedCount))
        if count != stagedCount { log.warning("Staged count \(stagedCount) differs from table rows \(count) for \(kind.rawValue, privacy: .public)") }
        guard count > 0 else { staged[kind] = 0; stagedRange[kind] = nil; return nil }
        let timeCol = SegmentSchema.timeColumn(kind)
        let range = stagedRange[kind] ?? (now, now)
        sequence += 1
        let relative = Self.relativePath(kind: kind, tier: .minute, start: range.0, sequence: sequence)
        let final = root.appending(path: relative)
        let tmp = root.appending(path: "tmp/\(final.lastPathComponent).tmp")
        try FileManager.default.createDirectory(at: final.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: root.appending(path: "tmp"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        do {
            let order = kind == .flows ? "start_time, src_ip" : "received_at"
            try engine.execute("""
                COPY (SELECT * FROM \(table) ORDER BY \(order)) TO \(DuckEngine.literal(tmp.path))
                (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE \(limits.rowGroupSize),
                 KV_METADATA { 'netsentry.schema_version': '\(SegmentSchema.version)', 'netsentry.kind': '\(kind.rawValue)', 'netsentry.origin': '\(origin.rawValue)' })
                """)
            let stats = try columnStats(table: table, kind: kind)
            let rawBytes = kind == .events ? (try rawColumnBytes(tmp.path)) : 0
            try Self.fsync(tmp)
            _ = try FileManager.default.replaceItemAt(final, withItemAt: tmp)
            chmod(final.path, 0o600)
            try Self.fsync(final.deletingLastPathComponent())
            let size = (try FileManager.default.attributesOfItem(atPath: final.path)[.size] as? Int64) ?? 0
            let digest = try Self.sha256(final)
            let record = SegmentRecord(kind: kind, tier: .minute, start: range.0, end: range.1, path: relative, rowCount: Int64(count), bytes: size, rawBytes: rawBytes,
                                       state: .finalized, schemaVersion: Int(SegmentSchema.version), enrichmentVersion: 1, parserVersions: nil,
                                       sha256: digest, createdAt: now, finalizedAt: .now, origin: origin)
            var stored = record
            stored.id = try await meta.insertSegment(record, stats: stats)
            if kind == .flows { try await writeRollups(origin: origin) }
            try engine.execute("DELETE FROM \(table)")
            staged[kind] = 0
            stagedRange[kind] = nil
            log.info("Finalized \(kind.rawValue, privacy: .public) segment \(relative, privacy: .public): \(count) rows, \(size) bytes")
            return stored
        } catch {
            writeFailures += 1
            try? FileManager.default.removeItem(at: tmp)
            log.error("Segment write failed for \(kind.rawValue, privacy: .public): \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }

    /// Per-minute rollups (client_id 0 = network totals) computed from the flow staging table before it is cleared.
    private func writeRollups(origin: Origin) async throws {
        let r = try engine.execute("""
            SELECT (start_time // 60000000) * 60000000 AS bucket, direction, COUNT(*)::BIGINT AS flows, SUM(packets)::BIGINT AS packets, SUM(octets)::BIGINT AS octets,
                   COALESCE(CASE WHEN direction = 2 THEN dst_client_id ELSE src_client_id END, 0)::BIGINT AS client
            FROM flows_stage GROUP BY 1, 2, 6
            """)
        // withExtendedLifetime: the result set must outlive the column reads (see DuckEngine.scalarInt64).
        let rows: [MetaStore.MinuteRollup] = withExtendedLifetime(r) {
        var rows: [MetaStore.MinuteRollup] = []
        let b = r[0].cast(to: Int64.self), d = r[1].cast(to: UInt8.self), f = r[2].cast(to: Int64.self), p = r[3].cast(to: Int64.self), o = r[4].cast(to: Int64.self), c = r[5].cast(to: Int64.self)
        // Network totals (client 0) plus per-client rows; totals are what the Overview reads, per-client rows feed baselines.
        var totals: [Int64: (UInt8, Int64, Int64, Int64)] = [:]
        for i in 0..<Int(r.rowCount) {
            let j = DBInt(i)
            let key = (b[j] ?? 0) &* 8 &+ Int64(d[j] ?? 0)
            var t = totals[key] ?? (d[j] ?? 0, 0, 0, 0); t.1 += f[j] ?? 0; t.2 += p[j] ?? 0; t.3 += o[j] ?? 0; totals[key] = t
            if let client = c[j], client != 0 {
                rows.append(.init(bucket: NetSentryCore.Timestamp(microseconds: b[j] ?? 0), origin: origin, clientID: client, direction: d[j] ?? 0, flows: f[j] ?? 0, packets: p[j] ?? 0, bytes: o[j] ?? 0, denied: 0, allowed: 0))
            }
        }
        for (key, t) in totals {
            rows.append(.init(bucket: NetSentryCore.Timestamp(microseconds: key / 8), origin: origin, clientID: 0, direction: t.0, flows: t.1, packets: t.2, bytes: t.3, denied: 0, allowed: 0))
        }
        return rows
        }
        try await meta.mergeMinuteRollups(rows)
        let h = try engine.execute("""
            SELECT (start_time // 3600000000) * 3600000000 AS bucket, dst_ip, dst_port, protocol, direction, dst_country, dst_asn,
                   COUNT(*)::BIGINT AS flows, SUM(octets)::BIGINT AS octets, SUM(packets)::BIGINT AS packets
            FROM flows_stage WHERE direction IN (1, 2) GROUP BY 1, 2, 3, 4, 5, 6, 7
            """)
        let hours: [MetaStore.HourRollup] = withExtendedLifetime(h) {
        var hours: [MetaStore.HourRollup] = []
        let hb = h[0].cast(to: Int64.self), ip = h[1].cast(to: String.self), port = h[2].cast(to: UInt16.self), proto = h[3].cast(to: UInt8.self)
        let dir = h[4].cast(to: UInt8.self), cc = h[5].cast(to: String.self), asn = h[6].cast(to: UInt32.self), hf = h[7].cast(to: Int64.self)
        let ho = h[8].cast(to: Int64.self), hp = h[9].cast(to: Int64.self)
        for i in 0..<Int(h.rowCount) {
            let j = DBInt(i)
            hours.append(.init(bucket: NetSentryCore.Timestamp(microseconds: hb[j] ?? 0), origin: origin, clientID: 0, dstIP: ip[j] ?? "", dstPort: Int(port[j] ?? 0),
                               protocolNumber: Int(proto[j] ?? 0), direction: dir[j] ?? 0, dstCountry: cc[j], dstASN: asn[j].map(Int64.init),
                               flows: hf[j] ?? 0, bytes: ho[j] ?? 0, packets: hp[j] ?? 0, denied: 0))
        }
        return hours
        }
        try await meta.mergeHourRollups(hours)
    }

    private func columnStats(table: String, kind: SegmentKind) throws -> [SegmentColumnStats] {
        let cols = kind == .flows ? ["start_time", "end_time", "src_v4", "dst_v4", "dst_port", "src_client_id", "dst_client_id"] : ["received_at", "src_v4", "dst_v4", "dst_port", "event_type", "severity"]
        var out: [SegmentColumnStats] = []
        for c in cols {
            let r = try engine.execute("SELECT MIN(\(c))::BIGINT, MAX(\(c))::BIGINT FROM \(table)")
            withExtendedLifetime(r) {
                guard r.rowCount > 0 else { return }
                let lo = r[0].cast(to: Int64.self), hi = r[1].cast(to: Int64.self)
                out.append(SegmentColumnStats(column: c, min: lo[0], max: hi[0]))
            }
        }
        return out
    }

    /// Compressed size of the raw-message columns, for the raw-syslog budget category.
    private func rawColumnBytes(_ path: String) throws -> Int64 {
        try engine.scalarInt64("SELECT COALESCE(SUM(total_compressed_size), 0)::BIGINT FROM parquet_metadata(\(DuckEngine.literal(path))) WHERE path_in_schema IN ('raw', 'raw_bytes')") ?? 0
    }

    public static func relativePath(kind: SegmentKind, tier: SegmentTier, start: NetSentryCore.Timestamp, sequence: Int64) -> String {
        var cal = Calendar(identifier: .gregorian); cal.timeZone = TimeZone(identifier: "UTC")!
        let c = cal.dateComponents([.year, .month, .day], from: start.date)
        let t = tier == .minute ? "m" : (tier == .hour ? "h" : "d")
        let dir = tier == .day ? String(format: "%@/%04d/%02d", kind.rawValue, c.year!, c.month!) : String(format: "%@/%04d/%02d/%02d", kind.rawValue, c.year!, c.month!, c.day!)
        return "\(dir)/\(kind.rawValue)_\(t)_\(start.seconds)_\(sequence).parquet"
    }

    static func fsync(_ url: URL) throws {
        let fd = open(url.path, O_RDONLY)
        guard fd >= 0 else { return }
        defer { close(fd) }
        _ = fcntl(fd, F_FULLFSYNC)
    }

    public static func sha256(_ url: URL) throws -> String {
        let h = try FileHandle(forReadingFrom: url)
        defer { try? h.close() }
        var hasher = SHA256()
        while let chunk = try h.read(upToCount: 4 << 20), !chunk.isEmpty { hasher.update(data: chunk) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
