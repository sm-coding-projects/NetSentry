import DuckDB
import Foundation
import NetSentryCore
import NetSentryPersistence
import os

/// Read-only analytical engine over a storage root: manifest-driven segment pruning + DuckDB over Parquet,
/// with rollups from SQLite for long-range charts. Used in-process by the dashboard; every query runs on
/// its own connection so ingestion (another process) and other queries are never blocked.
public actor ReadEngine {
    public let root: URL
    private let meta: MetaStore
    private let engine: DuckEngine
    private let log = Log.logger("analytics", process: "app")

    public init(root: URL, memoryLimit: String = "1GB", threads: Int = max(2, ProcessInfo.processInfo.activeProcessorCount / 2)) throws {
        self.root = root
        meta = try MetaStore(root: root, readOnly: true)
        engine = try DuckEngine(memoryLimit: memoryLimit, threads: threads)
    }

    // MARK: - Pruning

    /// Segments overlapping the filter's time range whose column statistics can match the filter.
    public func candidateSegments(kind: SegmentKind, filter: RecordFilter) async throws -> [SegmentRecord] {
        let segs = try await meta.segments(kind: kind, from: filter.range.start, to: filter.range.end, origin: filter.origin)
        var out: [SegmentRecord] = []
        for s in segs {
            let stats = try await meta.segmentStats(id: s.id)
            func within(_ col: String, _ value: Int64) -> Bool {
                guard let st = stats.first(where: { $0.column == col }), let lo = st.min, let hi = st.max else { return true }
                return value >= lo && value <= hi
            }
            if !filter.ports.isEmpty, !filter.ports.contains(where: { within("dst_port", Int64($0)) }) { continue }
            if let ip = filter.anyIP, let v = ip.v4Value, !within("src_v4", Int64(v)), !within("dst_v4", Int64(v)) { continue }
            if let ip = filter.srcIP, let v = ip.v4Value, !within("src_v4", Int64(v)) { continue }
            if let ip = filter.dstIP, let v = ip.v4Value, !within("dst_v4", Int64(v)) { continue }
            if let c = filter.clientID, !within("src_client_id", c), !within("dst_client_id", c) { continue }
            out.append(s)
        }
        return out
    }

    private func paths(_ segs: [SegmentRecord]) -> [String] { segs.map { root.appending(path: $0.path).path } }

    // MARK: - Execution

    private func run(_ c: SQLBuilder.Compiled) throws -> ResultSet {
        let conn = try engine.newConnection()
        let stmt = try PreparedStatement(connection: conn, query: c.sql)
        for (i, p) in c.params.enumerated() {
            switch p {
            case .int(let v): try stmt.bind(v, at: i + 1)
            case .uint(let v): try stmt.bind(v, at: i + 1)
            case .text(let v): try stmt.bind(v, at: i + 1)
            }
        }
        return try stmt.execute()
    }

    public func flows(_ q: FlowQuery) async throws -> QueryPage<FlowRecord> {
        let t0 = ContinuousClock.now
        let segs = try await candidateSegments(kind: .flows, filter: q.filter)
        try Task.checkCancellation()
        let r = try run(SQLBuilder.flows(q, paths: paths(segs)))
        try Task.checkCancellation()
        let rows = withExtendedLifetime(r) { RowMapper.flows(r) }
        var next: FlowQuery.Cursor?
        if rows.count >= q.limit, let last = rows.last { next = FlowQuery.Cursor(value: RowMapper.sortValue(last, q.sort), id: last.id) }
        return QueryPage(rows: rows, nextCursor: next, segmentsScanned: segs.count, elapsed: ContinuousClock.now - t0)
    }

    public func events(_ q: EventQuery) async throws -> QueryPage<SyslogEvent> {
        let t0 = ContinuousClock.now
        let segs = try await candidateSegments(kind: .events, filter: q.filter)
        try Task.checkCancellation()
        let r = try run(SQLBuilder.events(q, paths: paths(segs)))
        try Task.checkCancellation()
        let rows = withExtendedLifetime(r) { RowMapper.events(r) }
        var next: FlowQuery.Cursor?
        if rows.count >= q.limit, let last = rows.last { next = FlowQuery.Cursor(value: RowMapper.sortValue(last, q.sort), id: last.id) }
        return QueryPage(rows: rows, nextCursor: next, segmentsScanned: segs.count, elapsed: ContinuousClock.now - t0)
    }

    public func topN(_ q: TopNQuery) async throws -> [TopNRow] {
        let segs = try await candidateSegments(kind: .flows, filter: q.filter)
        try Task.checkCancellation()
        let r = try run(SQLBuilder.topN(q, paths: paths(segs)))
        return withExtendedLifetime(r) {
            let k = r[0].cast(to: String.self), f = r[1].cast(to: Int64.self), b = r[2].cast(to: Int64.self), p = r[3].cast(to: Int64.self)
            return (0..<Int(r.rowCount)).map { i in TopNRow(key: k[DBInt(i)] ?? "", flows: f[DBInt(i)] ?? 0, bytes: b[DBInt(i)] ?? 0, packets: p[DBInt(i)] ?? 0) }
        }
    }

    /// Bandwidth/flow counts over time. Filters that rollups cannot express (addresses, ports…) force a segment scan;
    /// otherwise minute rollups serve any range instantly.
    public func timeSeries(_ f: RecordFilter, bucket: Duration) async throws -> [TimeBucket] {
        let bucketMicros = max(60_000_000, bucket.microsecondsValue)
        let rollupOK = f.anyIP == nil && f.srcIP == nil && f.dstIP == nil && f.prefix == nil && f.clientID == nil && f.ports.isEmpty && f.protocols.isEmpty
            && f.countries.isEmpty && f.asns.isEmpty && f.vlans.isEmpty && f.exporterAddress == nil && f.minOctets == nil && f.minPackets == nil
        if rollupOK {
            // Minute rollups are aligned down: a range starting mid-minute includes that minute's bucket.
            var sql = "SELECT (bucket / ?) * ? AS b, SUM(flows), SUM(bytes), SUM(packets), SUM(CASE WHEN direction = 2 THEN bytes ELSE 0 END), SUM(CASE WHEN direction = 1 THEN bytes ELSE 0 END) FROM rollup_minute WHERE client_id = 0 AND bucket >= ? AND bucket <= ? AND origin = ?"
            var params: [any SQLBindable] = [bucketMicros, bucketMicros, f.range.start.truncated(to: 60_000_000), f.range.end, Int(f.origin.rawValue)]
            if !f.directions.isEmpty { sql += " AND direction IN (\(SQLBuilder.placeholders(f.directions.count)))"; params += f.directions.map { Int($0.rawValue) } }
            sql += " GROUP BY 1 ORDER BY 1"
            return try await meta.db.query(sql, params).map {
                TimeBucket(bucket: Timestamp(microseconds: $0[0].int64 ?? 0), flows: $0[1].int64 ?? 0, bytes: $0[2].int64 ?? 0, packets: $0[3].int64 ?? 0,
                           inboundBytes: $0[4].int64 ?? 0, outboundBytes: $0[5].int64 ?? 0)
            }
        }
        let segs = try await candidateSegments(kind: .flows, filter: f)
        try Task.checkCancellation()
        let r = try run(SQLBuilder.timeSeries(f, bucketMicros: bucketMicros, paths: paths(segs)))
        return withExtendedLifetime(r) {
            let cols = (0..<6).map { r[DBInt($0)].cast(to: Int64.self) }
            return (0..<Int(r.rowCount)).map { i in
                let j = DBInt(i)
                return TimeBucket(bucket: Timestamp(microseconds: cols[0][j] ?? 0), flows: cols[1][j] ?? 0, bytes: cols[2][j] ?? 0, packets: cols[3][j] ?? 0, inboundBytes: cols[4][j] ?? 0, outboundBytes: cols[5][j] ?? 0)
            }
        }
    }

    public func eventCounts(_ f: RecordFilter, by column: String) async throws -> [EventCountRow] {
        let segs = try await candidateSegments(kind: .events, filter: f)
        try Task.checkCancellation()
        let r = try run(SQLBuilder.eventCounts(f, by: column, paths: paths(segs)))
        return withExtendedLifetime(r) {
            let k = r[0].cast(to: String.self), n = r[1].cast(to: Int64.self)
            return (0..<Int(r.rowCount)).map { i in EventCountRow(key: k[DBInt(i)] ?? "", count: n[DBInt(i)] ?? 0) }
        }
    }

    /// Totals for a range (flows, bytes, in/out) from rollups.
    public func totals(_ range: TimeRange, origin: Origin = .live) async throws -> TimeBucket {
        let row = try await meta.db.query("SELECT SUM(flows), SUM(bytes), SUM(packets), SUM(CASE WHEN direction = 2 THEN bytes ELSE 0 END), SUM(CASE WHEN direction = 1 THEN bytes ELSE 0 END) FROM rollup_minute WHERE client_id = 0 AND bucket >= ? AND bucket <= ? AND origin = ?",
                                          [range.start.truncated(to: 60_000_000), range.end, Int(origin.rawValue)]).first
        return TimeBucket(bucket: range.start, flows: row?[0].int64 ?? 0, bytes: row?[1].int64 ?? 0, packets: row?[2].int64 ?? 0, inboundBytes: row?[3].int64 ?? 0, outboundBytes: row?[4].int64 ?? 0)
    }

    public func gaps(_ range: TimeRange) async throws -> [CollectionGap] { try await meta.gaps(from: range.start, to: range.end) }
    public func segmentCount() async throws -> Int { try await meta.segments().count }
}

/// Maps DuckDB result columns (by name) back onto the domain records.
enum RowMapper {
    private struct Cols {
        let r: ResultSet
        var index: [String: DBInt] = [:]
        init(_ r: ResultSet) { self.r = r; for i in 0..<r.columnCount { index[r.columnName(at: i)] = i } }
        func i64(_ n: String, _ row: DBInt) -> Int64? { index[n].flatMap { r[$0].cast(to: Int64.self)[row] } }
        func u64(_ n: String, _ row: DBInt) -> UInt64? { index[n].flatMap { r[$0].cast(to: UInt64.self)[row] } }
        func u32(_ n: String, _ row: DBInt) -> UInt32? { index[n].flatMap { r[$0].cast(to: UInt32.self)[row] } }
        func u16(_ n: String, _ row: DBInt) -> UInt16? { index[n].flatMap { r[$0].cast(to: UInt16.self)[row] } }
        func u8(_ n: String, _ row: DBInt) -> UInt8? { index[n].flatMap { r[$0].cast(to: UInt8.self)[row] } }
        func str(_ n: String, _ row: DBInt) -> String? { index[n].flatMap { r[$0].cast(to: String.self)[row] } }
        func bool(_ n: String, _ row: DBInt) -> Bool? { index[n].flatMap { r[$0].cast(to: Bool.self)[row] } }
        func data(_ n: String, _ row: DBInt) -> Data? { index[n].flatMap { r[$0].cast(to: Data.self)[row] } }
    }

    static func flows(_ r: ResultSet) -> [FlowRecord] {
        let c = Cols(r)
        return (0..<Int(r.rowCount)).map { i in
            let j = DBInt(i)
            let exporter = ExporterKey(address: IPAddress(c.str("exporter_addr", j) ?? "") ?? IPAddress(v4: 0), observationDomain: c.u32("observation_domain_id", j) ?? 0)
            var f = FlowRecord(exporter: exporter, exportSequence: c.u32("export_seq", j) ?? 0,
                               receivedAt: Timestamp(microseconds: c.i64("received_at", j) ?? 0), exportTime: Timestamp(microseconds: c.i64("export_time", j) ?? 0),
                               startTime: Timestamp(microseconds: c.i64("start_time", j) ?? 0), endTime: Timestamp(microseconds: c.i64("end_time", j) ?? 0),
                               srcIP: IPAddress(c.str("src_ip", j) ?? "") ?? IPAddress(v4: 0), dstIP: IPAddress(c.str("dst_ip", j) ?? "") ?? IPAddress(v4: 0))
            f.id = c.i64("flow_id", j) ?? 0
            f.origin = Origin(rawValue: c.u8("origin", j) ?? 0) ?? .live
            f.exporterID = Int32(truncatingIfNeeded: c.i64("exporter_id", j) ?? 0)
            f.clockSkewMicroseconds = c.i64("clock_skew_us", j) ?? 0
            f.srcPort = c.u16("src_port", j) ?? 0; f.dstPort = c.u16("dst_port", j) ?? 0
            f.protocolNumber = c.u8("protocol", j) ?? 0; f.tcpFlags = c.u16("tcp_flags", j) ?? 0
            f.icmpType = c.u8("icmp_type", j); f.icmpCode = c.u8("icmp_code", j)
            f.packets = c.u64("packets", j) ?? 0; f.octets = c.u64("octets", j) ?? 0
            f.reversePackets = c.u64("rev_packets", j); f.reverseOctets = c.u64("rev_octets", j)
            f.ingressInterface = c.u32("ingress_if", j); f.egressInterface = c.u32("egress_if", j)
            f.srcVLAN = c.u16("src_vlan", j); f.dstVLAN = c.u16("dst_vlan", j)
            f.flowDirection = c.u8("flow_direction", j); f.flowEndReason = c.u8("flow_end_reason", j); f.samplingInterval = c.u32("sampling_interval", j)
            f.postNATSrcIP = c.str("post_nat_src_ip", j).flatMap(IPAddress.init); f.postNATDstIP = c.str("post_nat_dst_ip", j).flatMap(IPAddress.init)
            f.postNATSrcPort = c.u16("post_nat_src_port", j); f.postNATDstPort = c.u16("post_nat_dst_port", j)
            f.applicationID = c.str("app_id", j)
            if let extra = c.str("ie_extra", j), let d = extra.data(using: .utf8), let dict = try? JSONDecoder().decode([String: String].self, from: d) {
                f.extraElements = dict.compactMap { k, v in
                    let parts = k.split(separator: ":"); guard parts.count == 2, let pen = UInt32(parts[0]), let id = UInt16(parts[1]), let bytes = Data(base64Encoded: v) else { return nil }
                    return RawInformationElement(enterpriseNumber: pen, elementID: id, value: bytes)
                }.sorted { $0.elementID < $1.elementID }
            }
            f.enrichment.direction = TrafficDirection(rawValue: c.u8("direction", j) ?? 0) ?? .unknown
            f.enrichment.srcInternal = c.bool("src_internal", j) ?? false; f.enrichment.dstInternal = c.bool("dst_internal", j) ?? false
            f.enrichment.srcClientID = c.i64("src_client_id", j); f.enrichment.dstClientID = c.i64("dst_client_id", j)
            f.enrichment.srcCountry = c.str("src_country", j); f.enrichment.dstCountry = c.str("dst_country", j)
            f.enrichment.srcASN = c.u32("src_asn", j); f.enrichment.dstASN = c.u32("dst_asn", j)
            f.enrichment.dstOrganization = c.str("dst_org", j); f.enrichment.service = c.str("service", j)
            f.enrichment.enrichmentVersion = c.u16("enrichment_version", j) ?? 0
            return f
        }
    }

    static func events(_ r: ResultSet) -> [SyslogEvent] {
        let c = Cols(r)
        return (0..<Int(r.rowCount)).map { i in
            let j = DBInt(i)
            var e = SyslogEvent(receivedAt: Timestamp(microseconds: c.i64("received_at", j) ?? 0), sourceIP: IPAddress(c.str("source_ip", j) ?? "") ?? IPAddress(v4: 0),
                                transport: Transport(rawValue: c.u8("transport", j) ?? 0) ?? .udp, message: c.str("message", j) ?? "", raw: c.str("raw", j))
            e.id = c.i64("event_id", j) ?? 0
            e.origin = Origin(rawValue: c.u8("origin", j) ?? 0) ?? .live
            e.eventTime = c.i64("event_time", j).map { Timestamp(microseconds: $0) }
            e.timeInferred = c.bool("time_inferred", j) ?? false
            e.syslogVersion = c.u8("syslog_version", j) ?? 0
            e.facility = SyslogFacility(rawValue: c.u8("facility", j) ?? 1) ?? .user
            e.severity = SyslogSeverity(rawValue: c.u8("severity", j) ?? 6) ?? .informational
            e.priorityPresent = c.bool("priority_present", j) ?? true
            e.hostname = c.str("hostname", j); e.appName = c.str("app_name", j); e.procID = c.str("proc_id", j); e.msgID = c.str("msg_id", j)
            if let sd = c.str("structured_data", j), let d = sd.data(using: .utf8) { e.structuredData = (try? JSONDecoder().decode([String: [String: String]].self, from: d)) ?? [:] }
            e.rawBytes = c.data("raw_bytes", j)
            e.parserName = c.str("parser_name", j) ?? "unknown"; e.parserVersion = c.u16("parser_version", j) ?? 0
            e.parseStatus = ParseStatus(rawValue: c.u8("parse_status", j) ?? 2) ?? .unparsed
            e.eventType = EventType(rawValue: c.u8("event_type", j) ?? 0) ?? .unknown
            e.srcIP = c.str("src_ip", j).flatMap(IPAddress.init); e.dstIP = c.str("dst_ip", j).flatMap(IPAddress.init)
            e.srcPort = c.u16("src_port", j); e.dstPort = c.u16("dst_port", j); e.protocolNumber = c.u8("protocol", j)
            e.action = c.u8("action", j).flatMap(FirewallAction.init)
            e.inInterface = c.str("in_iface", j); e.outInterface = c.str("out_iface", j); e.vlan = c.u16("vlan", j)
            e.ruleID = c.str("rule_id", j); e.ruleName = c.str("rule_name", j); e.username = c.str("username", j); e.deviceID = c.str("device_id", j)
            e.idsSignatureID = c.i64("ids_signature_id", j); e.idsSignature = c.str("ids_signature", j); e.idsCategory = c.str("ids_category", j); e.idsSeverity = c.u8("ids_severity", j)
            e.enrichment.srcClientID = c.i64("src_client_id", j); e.enrichment.dstClientID = c.i64("dst_client_id", j)
            e.enrichment.direction = TrafficDirection(rawValue: c.u8("direction", j) ?? 0) ?? .unknown
            e.enrichment.srcInternal = c.bool("src_internal", j) ?? false; e.enrichment.dstInternal = c.bool("dst_internal", j) ?? false
            e.enrichment.dstCountry = c.str("dst_country", j); e.enrichment.dstASN = c.u32("dst_asn", j)
            if let a = c.str("attrs", j), let d = a.data(using: .utf8) { e.attributes = (try? JSONDecoder().decode([String: String].self, from: d)) ?? [:] }
            e.enrichment.enrichmentVersion = c.u16("enrichment_version", j) ?? 0
            return e
        }
    }

    static func sortValue(_ f: FlowRecord, _ key: FlowSortKey) -> Int64 {
        switch key {
        case .startTime: f.startTime.microseconds
        case .endTime: f.endTime.microseconds
        case .octets: Int64(clamping: f.octets)
        case .packets: Int64(clamping: f.packets)
        case .dstPort: Int64(f.dstPort)
        case .protocolNumber: Int64(f.protocolNumber)
        case .duration: f.endTime.microseconds - f.startTime.microseconds
        case .srcIP, .dstIP: f.startTime.microseconds   // string sorts page by time as a fallback
        }
    }
    static func sortValue(_ e: SyslogEvent, _ key: EventSortKey) -> Int64 {
        switch key {
        case .receivedAt: e.receivedAt.microseconds
        case .eventTime: e.eventTime?.microseconds ?? e.receivedAt.microseconds
        case .severity: Int64(e.severity.rawValue)
        case .eventType: Int64(e.eventType.rawValue)
        case .srcIP, .dstIP: e.receivedAt.microseconds
        }
    }
}
