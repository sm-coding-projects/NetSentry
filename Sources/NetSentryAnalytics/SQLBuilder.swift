import Foundation
import NetSentryCore
import NetSentryPersistence

/// Compiles typed queries into DuckDB SQL with positional `?` parameters (bound through PreparedStatement).
struct SQLBuilder {
    struct Compiled { var sql: String; var params: [SQLParam] }
    enum SQLParam: Sendable { case int(Int64), text(String), uint(UInt64) }

    /// `read_parquet([...])` source for a set of segment paths; empty list yields an empty relation with the right schema.
    static func source(kind: SegmentKind, paths: [String]) -> String {
        guard !paths.isEmpty else {
            let cols = (kind == .flows ? SegmentSchema.flowColumns : SegmentSchema.eventColumns).map { "NULL::\($0.1) AS \($0.0)" }.joined(separator: ", ")
            return "(SELECT \(cols) WHERE false)"
        }
        return "read_parquet(\(DuckEngine.pathList(paths)), union_by_name = true)"
    }

    static func whereClause(_ f: RecordFilter, kind: SegmentKind) -> Compiled {
        var clauses: [String] = []
        var params: [SQLParam] = []
        let timeCol = SegmentSchema.timeColumn(kind)
        clauses.append("\(timeCol) >= ? AND \(timeCol) <= ?"); params += [.int(f.range.start.microseconds), .int(f.range.end.microseconds)]
        clauses.append("origin = ?"); params.append(.int(Int64(f.origin.rawValue)))
        if let ip = f.anyIP { clauses.append("(src_ip = ? OR dst_ip = ?)"); params += [.text(ip.description), .text(ip.description)] }
        if let ip = f.srcIP { clauses.append("src_ip = ?"); params.append(.text(ip.description)) }
        if let ip = f.dstIP { clauses.append("dst_ip = ?"); params.append(.text(ip.description)) }
        if let p = f.prefix, let net = p.network.v4Value {
            let mask: UInt32 = p.prefixLength == 0 ? 0 : (p.prefixLength >= 32 ? .max : ~(UInt32.max >> UInt32(p.prefixLength)))
            let lo = Int64(net & mask), hi = Int64((net & mask) | ~mask)
            clauses.append("((src_v4 BETWEEN ? AND ?) OR (dst_v4 BETWEEN ? AND ?))"); params += [.int(lo), .int(hi), .int(lo), .int(hi)]
        }
        if let c = f.clientID { clauses.append("(src_client_id = ? OR dst_client_id = ?)"); params += [.int(c), .int(c)] }
        if !f.ports.isEmpty { clauses.append("dst_port IN (\(placeholders(f.ports.count)))"); params += f.ports.map { .int(Int64($0)) } }
        if !f.protocols.isEmpty { clauses.append("protocol IN (\(placeholders(f.protocols.count)))"); params += f.protocols.map { .int(Int64($0)) } }
        if !f.directions.isEmpty { clauses.append("direction IN (\(placeholders(f.directions.count)))"); params += f.directions.map { .int(Int64($0.rawValue)) } }
        if !f.countries.isEmpty { clauses.append("dst_country IN (\(placeholders(f.countries.count)))"); params += f.countries.map { .text($0) } }
        if !f.asns.isEmpty { clauses.append("dst_asn IN (\(placeholders(f.asns.count)))"); params += f.asns.map { .int(Int64($0)) } }
        if let e = f.exporterAddress {
            if kind == .flows { clauses.append("exporter_addr = ?") } else { clauses.append("source_ip = ?") }
            params.append(.text(e.description))
        }
        if kind == .flows {
            if !f.vlans.isEmpty { clauses.append("(src_vlan IN (\(placeholders(f.vlans.count))) OR dst_vlan IN (\(placeholders(f.vlans.count))))"); params += f.vlans.map { .int(Int64($0)) } + f.vlans.map { .int(Int64($0)) } }
            if let m = f.minOctets { clauses.append("octets >= ?"); params.append(.uint(m)) }
            if let m = f.minPackets { clauses.append("packets >= ?"); params.append(.uint(m)) }
        } else {
            if !f.vlans.isEmpty { clauses.append("vlan IN (\(placeholders(f.vlans.count)))"); params += f.vlans.map { .int(Int64($0)) } }
            if !f.actions.isEmpty { clauses.append("action IN (\(placeholders(f.actions.count)))"); params += f.actions.map { .int(Int64($0.rawValue)) } }
            if !f.severities.isEmpty { clauses.append("severity IN (\(placeholders(f.severities.count)))"); params += f.severities.map { .int(Int64($0.rawValue)) } }
            if !f.eventTypes.isEmpty { clauses.append("event_type IN (\(placeholders(f.eventTypes.count)))"); params += f.eventTypes.map { .int(Int64($0.rawValue)) } }
            if let s = f.idsSignature, !s.isEmpty { clauses.append("contains(lower(coalesce(ids_signature, '')), lower(?))"); params.append(.text(s)) }
            if let t = f.text, !t.isEmpty { clauses.append("(contains(lower(message), lower(?)) OR contains(lower(coalesce(rule_name, '')), lower(?)) OR contains(lower(coalesce(hostname, '')), lower(?)))"); params += [.text(t), .text(t), .text(t)] }
        }
        return Compiled(sql: clauses.joined(separator: " AND "), params: params)
    }

    static func placeholders(_ n: Int) -> String { Array(repeating: "?", count: n).joined(separator: ", ") }

    static func flows(_ q: FlowQuery, paths: [String]) -> Compiled {
        var w = whereClause(q.filter, kind: .flows)
        let sortExpr = q.sort.rawValue
        if let c = q.cursor {
            let op = q.direction == .descending ? "<" : ">"
            w.sql += " AND ((\(sortExpr) \(op) ?) OR (\(sortExpr) = ? AND flow_id \(op) ?))"
            w.params += [.int(c.value), .int(c.value), .int(c.id)]
        }
        let sql = "SELECT * FROM \(source(kind: .flows, paths: paths)) WHERE \(w.sql) ORDER BY \(sortExpr) \(q.direction.rawValue), flow_id \(q.direction.rawValue) LIMIT \(max(1, min(q.limit, 10_000)))"
        return Compiled(sql: sql, params: w.params)
    }

    static func events(_ q: EventQuery, paths: [String]) -> Compiled {
        var w = whereClause(q.filter, kind: .events)
        let sortExpr = q.sort.rawValue
        if let c = q.cursor {
            let op = q.direction == .descending ? "<" : ">"
            w.sql += " AND ((\(sortExpr) \(op) ?) OR (\(sortExpr) = ? AND event_id \(op) ?))"
            w.params += [.int(c.value), .int(c.value), .int(c.id)]
        }
        let sql = "SELECT * FROM \(source(kind: .events, paths: paths)) WHERE \(w.sql) ORDER BY \(sortExpr) \(q.direction.rawValue), event_id \(q.direction.rawValue) LIMIT \(max(1, min(q.limit, 10_000)))"
        return Compiled(sql: sql, params: w.params)
    }

    static func topN(_ q: TopNQuery, paths: [String]) -> Compiled {
        let w = whereClause(q.filter, kind: .flows)
        let dim = q.dimension.rawValue
        let sql = "SELECT CAST(\(dim) AS VARCHAR) AS k, COUNT(*)::BIGINT AS flows, SUM(octets)::BIGINT AS bytes, SUM(packets)::BIGINT AS packets FROM \(source(kind: .flows, paths: paths)) WHERE \(w.sql) AND \(dim) IS NOT NULL GROUP BY 1 ORDER BY bytes DESC LIMIT \(max(1, min(q.limit, 1_000)))"
        return Compiled(sql: sql, params: w.params)
    }

    static func timeSeries(_ f: RecordFilter, bucketMicros: Int64, paths: [String]) -> Compiled {
        let w = whereClause(f, kind: .flows)
        let sql = """
            SELECT (start_time // \(bucketMicros)) * \(bucketMicros) AS bucket, COUNT(*)::BIGINT AS flows, SUM(octets)::BIGINT AS bytes, SUM(packets)::BIGINT AS packets,
                   SUM(CASE WHEN direction = 2 THEN octets ELSE 0 END)::BIGINT AS inbound, SUM(CASE WHEN direction = 1 THEN octets ELSE 0 END)::BIGINT AS outbound
            FROM \(source(kind: .flows, paths: paths)) WHERE \(w.sql) GROUP BY 1 ORDER BY 1
            """
        return Compiled(sql: sql, params: w.params)
    }

    static func eventCounts(_ f: RecordFilter, by column: String, paths: [String]) -> Compiled {
        let w = whereClause(f, kind: .events)
        let allowed = ["severity", "event_type", "action", "rule_name", "ids_signature", "ids_category", "src_ip", "dst_ip", "hostname", "app_name", "parser_name"]
        precondition(allowed.contains(column))
        let sql = "SELECT CAST(coalesce(CAST(\(column) AS VARCHAR), '') AS VARCHAR) AS k, COUNT(*)::BIGINT AS n FROM \(source(kind: .events, paths: paths)) WHERE \(w.sql) GROUP BY 1 ORDER BY n DESC LIMIT 200"
        return Compiled(sql: sql, params: w.params)
    }
}
