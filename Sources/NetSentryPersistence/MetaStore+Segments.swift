import Foundation
import NetSentryCore

/// Segment manifest operations (all writes are transactional).
extension MetaStore {
    public func insertSegment(_ s: SegmentRecord, stats: [SegmentColumnStats]) throws -> Int64 {
        try db.transaction {
            try db.run("""
                INSERT INTO segments (kind, tier, start_ts, end_ts, path, row_count, bytes, raw_bytes, compacted, state, schema_version, enrichment_version,
                  parser_versions_json, sha256, created_at, finalized_at, origin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [s.kind.rawValue, s.tier.rawValue, s.start, s.end, s.path, s.rowCount, s.bytes, s.rawBytes, s.compacted, s.state.rawValue,
                      s.schemaVersion, s.enrichmentVersion, s.parserVersions, s.sha256, s.createdAt, s.finalizedAt, Int(s.origin.rawValue)])
            let id = db.lastInsertRowID
            for st in stats {
                try db.run("INSERT OR REPLACE INTO segment_stats (segment_id, column, min_value, max_value, distinct_estimate) VALUES (?, ?, ?, ?, ?)",
                           [id, st.column, st.min, st.max, st.distinctEstimate])
            }
            return id
        }
    }

    public func setSegmentState(_ id: Int64, _ state: SegmentState) throws {
        try db.run("UPDATE segments SET state = ? WHERE id = ?", [state.rawValue, id])
    }

    public func updateSegmentAfterRewrite(_ id: Int64, path: String, bytes: Int64, rawBytes: Int64, rowCount: Int64, sha256: String?, compacted: Bool, tier: SegmentTier) throws {
        try db.run("UPDATE segments SET path = ?, bytes = ?, raw_bytes = ?, row_count = ?, sha256 = ?, compacted = ?, tier = ?, state = 'finalized' WHERE id = ?",
                   [path, bytes, rawBytes, rowCount, sha256, compacted, tier.rawValue, id])
    }

    /// Repairs a manifest row whose file is intact (checksum matches) but whose recorded row count drifted.
    public func setSegmentRowCount(_ id: Int64, rowCount: Int64) throws {
        try db.run("UPDATE segments SET row_count = ?, state = 'finalized' WHERE id = ?", [rowCount, id])
    }

    public func deleteSegments(ids: [Int64]) throws {
        try db.transaction {
            for id in ids { try db.run("UPDATE segments SET state = 'deleted' WHERE id = ?", [id]) }
        }
    }

    public func purgeDeletedSegments() throws { try db.run("DELETE FROM segments WHERE state = 'deleted'") }

    public func segments(kind: SegmentKind? = nil, states: [SegmentState] = [.finalized], from: Timestamp? = nil, to: Timestamp? = nil, origin: Origin? = nil) throws -> [SegmentRecord] {
        var sql = "SELECT * FROM segments WHERE state IN (\(states.map { _ in "?" }.joined(separator: ",")))"
        var params: [any SQLBindable] = states.map(\.rawValue)
        if let kind { sql += " AND kind = ?"; params.append(kind.rawValue) }
        if let from { sql += " AND end_ts >= ?"; params.append(from) }
        if let to { sql += " AND start_ts <= ?"; params.append(to) }
        if let origin { sql += " AND origin = ?"; params.append(Int(origin.rawValue)) }
        sql += " ORDER BY start_ts, id"
        return try db.query(sql, params).map(Self.segment(from:))
    }

    public func allSegments() throws -> [SegmentRecord] {
        try db.query("SELECT * FROM segments ORDER BY start_ts, id").map(Self.segment(from:))
    }

    public func segmentStats(id: Int64) throws -> [SegmentColumnStats] {
        try db.query("SELECT column, min_value, max_value, distinct_estimate FROM segment_stats WHERE segment_id = ?", [id]).map {
            SegmentColumnStats(column: $0.string("column") ?? "", min: $0.int64("min_value"), max: $0.int64("max_value"), distinctEstimate: $0.int64("distinct_estimate"))
        }
    }

    /// Bytes per (kind, tier) for finalized segments, plus raw bytes inside event segments.
    public func segmentUsage() throws -> (flows: Int64, events: Int64, raw: Int64, count: Int, oldest: Timestamp?, newest: Timestamp?) {
        let r = try db.query("""
            SELECT kind, SUM(bytes) AS b, SUM(raw_bytes) AS r, COUNT(*) AS n, MIN(start_ts) AS o, MAX(end_ts) AS w FROM segments
            WHERE state IN ('finalized','compacting') GROUP BY kind
            """)
        var flows: Int64 = 0, events: Int64 = 0, raw: Int64 = 0, n = 0
        var oldest: Timestamp?, newest: Timestamp?
        for row in r {
            if row.string("kind") == "flows" { flows = row.int64("b") ?? 0 } else { events = row.int64("b") ?? 0; raw = row.int64("r") ?? 0 }
            n += row.int("n") ?? 0
            if let o = row.timestamp("o"), oldest == nil || o < oldest! { oldest = o }
            if let w = row.timestamp("w"), newest == nil || w > newest! { newest = w }
        }
        return (flows, events, raw, n, oldest, newest)
    }

    public func nextSegmentSequence() throws -> Int64 { (try db.scalar("SELECT COALESCE(MAX(id), 0) + 1 FROM segments").int64) ?? 1 }

    static func segment(from r: SQLRow) -> SegmentRecord {
        SegmentRecord(id: r.int64("id") ?? 0, kind: SegmentKind(rawValue: r.string("kind") ?? "flows") ?? .flows, tier: SegmentTier(rawValue: r.string("tier") ?? "minute") ?? .minute,
                      start: r.timestamp("start_ts") ?? Timestamp(microseconds: 0), end: r.timestamp("end_ts") ?? Timestamp(microseconds: 0), path: r.string("path") ?? "",
                      rowCount: r.int64("row_count") ?? 0, bytes: r.int64("bytes") ?? 0, rawBytes: r.int64("raw_bytes") ?? 0, compacted: r.bool("compacted"),
                      state: SegmentState(rawValue: r.string("state") ?? "finalized") ?? .finalized, schemaVersion: r.int("schema_version") ?? 1,
                      enrichmentVersion: r.int("enrichment_version") ?? 0, parserVersions: r.string("parser_versions_json"), sha256: r.string("sha256"),
                      createdAt: r.timestamp("created_at") ?? Timestamp(microseconds: 0), finalizedAt: r.timestamp("finalized_at"),
                      origin: Origin(rawValue: UInt8(r.int("origin") ?? 0)) ?? .live)
    }

    // MARK: Rollups

    public struct MinuteRollup: Sendable, Hashable {
        public var bucket: Timestamp; public var origin: Origin; public var clientID: Int64; public var direction: UInt8
        public var flows: Int64; public var packets: Int64; public var bytes: Int64; public var denied: Int64; public var allowed: Int64
        public init(bucket: Timestamp, origin: Origin, clientID: Int64, direction: UInt8, flows: Int64, packets: Int64, bytes: Int64, denied: Int64, allowed: Int64) {
            self.bucket = bucket; self.origin = origin; self.clientID = clientID; self.direction = direction; self.flows = flows; self.packets = packets; self.bytes = bytes; self.denied = denied; self.allowed = allowed
        }
    }

    public func mergeMinuteRollups(_ rows: [MinuteRollup]) throws {
        guard !rows.isEmpty else { return }
        try db.transaction {
            for r in rows {
                try db.run("""
                    INSERT INTO rollup_minute (bucket, origin, client_id, direction, flows, packets, bytes, denied, allowed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket, origin, client_id, direction) DO UPDATE SET flows = flows + excluded.flows, packets = packets + excluded.packets,
                      bytes = bytes + excluded.bytes, denied = denied + excluded.denied, allowed = allowed + excluded.allowed
                    """, [r.bucket, Int(r.origin.rawValue), r.clientID, Int(r.direction), r.flows, r.packets, r.bytes, r.denied, r.allowed])
            }
        }
    }

    public struct HourRollup: Sendable, Hashable {
        public var bucket: Timestamp; public var origin: Origin; public var clientID: Int64; public var dstIP: String; public var dstPort: Int; public var protocolNumber: Int
        public var direction: UInt8; public var dstCountry: String?; public var dstASN: Int64?; public var flows: Int64; public var bytes: Int64; public var packets: Int64; public var denied: Int64
        public init(bucket: Timestamp, origin: Origin, clientID: Int64, dstIP: String, dstPort: Int, protocolNumber: Int, direction: UInt8, dstCountry: String?, dstASN: Int64?, flows: Int64, bytes: Int64, packets: Int64, denied: Int64) {
            self.bucket = bucket; self.origin = origin; self.clientID = clientID; self.dstIP = dstIP; self.dstPort = dstPort; self.protocolNumber = protocolNumber; self.direction = direction
            self.dstCountry = dstCountry; self.dstASN = dstASN; self.flows = flows; self.bytes = bytes; self.packets = packets; self.denied = denied
        }
    }

    public func mergeHourRollups(_ rows: [HourRollup]) throws {
        guard !rows.isEmpty else { return }
        try db.transaction {
            for r in rows {
                try db.run("""
                    INSERT INTO rollup_hour (bucket, origin, client_id, dst_ip, dst_port, protocol, direction, dst_country, dst_asn, flows, bytes, packets, denied)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket, origin, client_id, dst_ip, dst_port, protocol, direction) DO UPDATE SET flows = flows + excluded.flows,
                      bytes = bytes + excluded.bytes, packets = packets + excluded.packets, denied = denied + excluded.denied,
                      dst_country = COALESCE(excluded.dst_country, dst_country), dst_asn = COALESCE(excluded.dst_asn, dst_asn)
                    """, [r.bucket, Int(r.origin.rawValue), r.clientID, r.dstIP, r.dstPort, r.protocolNumber, Int(r.direction), r.dstCountry, r.dstASN, r.flows, r.bytes, r.packets, r.denied])
            }
        }
    }
}
