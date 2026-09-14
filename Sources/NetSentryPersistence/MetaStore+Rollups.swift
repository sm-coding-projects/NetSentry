import Foundation
import NetSentryCore

public struct DayRollup: Sendable, Hashable {
    public var bucket: Timestamp, origin: Origin, clientID: Int64, dstCountry: String, dstASN: Int64, dstPort: Int, protocolNumber: Int, flows: Int64, bytes: Int64, denied: Int64
}

extension MetaStore {
    public static let dayMicros: Int64 = 86_400_000_000

    /// Builds the day tier for one UTC day from the hour tier (idempotent; replaces existing rows for that day).
    /// Returns the number of day rows written.
    @discardableResult
    public func buildDayRollups(day: Timestamp, origin: Origin) throws -> Int {
        let start = day.truncated(to: Self.dayMicros), end = Timestamp(microseconds: start.microseconds + Self.dayMicros)
        return try db.transaction {
            try db.run("DELETE FROM rollup_day WHERE bucket = ? AND origin = ?", [start, Int(origin.rawValue)])
            return try db.run("""
                INSERT INTO rollup_day (bucket, origin, client_id, dst_country, dst_asn, dst_port, protocol, flows, bytes, denied, first_seen_new)
                SELECT ?, origin, client_id, COALESCE(dst_country, ''), COALESCE(dst_asn, 0), dst_port, protocol, SUM(flows), SUM(bytes), SUM(denied), 0
                FROM rollup_hour WHERE bucket >= ? AND bucket < ? AND origin = ?
                GROUP BY origin, client_id, COALESCE(dst_country, ''), COALESCE(dst_asn, 0), dst_port, protocol
                """, [start, start, end, Int(origin.rawValue)])
        }
    }

    public func dayRollups(from: Timestamp, to: Timestamp, origin: Origin) throws -> [DayRollup] {
        try db.query("SELECT * FROM rollup_day WHERE bucket >= ? AND bucket <= ? AND origin = ? ORDER BY bucket", [from, to, Int(origin.rawValue)]).map { r in
            DayRollup(bucket: r.timestamp("bucket") ?? .init(microseconds: 0), origin: origin, clientID: r.int64("client_id") ?? 0, dstCountry: r.string("dst_country") ?? "", dstASN: r.int64("dst_asn") ?? 0,
                      dstPort: r.int("dst_port") ?? 0, protocolNumber: r.int("protocol") ?? 0, flows: r.int64("flows") ?? 0, bytes: r.int64("bytes") ?? 0, denied: r.int64("denied") ?? 0)
        }
    }

    /// One JSON document per day: totals by direction, top clients/destinations/ports/countries, alert counts.
    /// This is what the daily digest and long-range Overview read once detailed rollups have been retired.
    public func buildDailySummary(day: Timestamp, origin: Origin) throws -> String {
        let start = day.truncated(to: Self.dayMicros), end = Timestamp(microseconds: start.microseconds + Self.dayMicros)
        let o = Int(origin.rawValue)
        var doc: [String: Any] = ["day": ISO8601DateFormatter().string(from: start.date), "origin": origin.rawValue, "version": 1]
        var totals: [String: [String: Int64]] = [:]
        for r in try db.query("SELECT direction, SUM(flows), SUM(bytes), SUM(packets) FROM rollup_minute WHERE client_id = 0 AND bucket >= ? AND bucket < ? AND origin = ? GROUP BY 1", [start, end, o]) {
            let d = TrafficDirection(rawValue: UInt8(r[0].int64 ?? 0)) ?? .unknown
            totals[d.label.lowercased()] = ["flows": r[1].int64 ?? 0, "bytes": r[2].int64 ?? 0, "packets": r[3].int64 ?? 0]
        }
        doc["totals"] = totals
        doc["topClients"] = try db.query("SELECT client_id, SUM(bytes), SUM(flows) FROM rollup_minute WHERE client_id != 0 AND direction = ? AND bucket >= ? AND bucket < ? AND origin = ? GROUP BY 1 ORDER BY 2 DESC LIMIT 20",
                                         [Int(TrafficDirection.outbound.rawValue), start, end, o]).map { ["client": $0[0].int64 ?? 0, "bytes": $0[1].int64 ?? 0, "flows": $0[2].int64 ?? 0] as [String: Int64] }
        doc["topDestinations"] = try db.query("SELECT dst_ip, SUM(bytes), SUM(flows) FROM rollup_hour WHERE dst_ip != '' AND bucket >= ? AND bucket < ? AND origin = ? GROUP BY 1 ORDER BY 2 DESC LIMIT 20", [start, end, o])
            .map { ["ip": $0[0].string ?? "", "bytes": "\($0[1].int64 ?? 0)", "flows": "\($0[2].int64 ?? 0)"] as [String: String] }
        doc["topPorts"] = try db.query("SELECT dst_port, protocol, SUM(flows), SUM(bytes) FROM rollup_hour WHERE bucket >= ? AND bucket < ? AND origin = ? GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 20", [start, end, o])
            .map { ["port": $0[0].int64 ?? 0, "protocol": $0[1].int64 ?? 0, "flows": $0[2].int64 ?? 0, "bytes": $0[3].int64 ?? 0] as [String: Int64] }
        doc["topCountries"] = try db.query("SELECT COALESCE(dst_country, ''), SUM(bytes), SUM(flows) FROM rollup_hour WHERE bucket >= ? AND bucket < ? AND origin = ? GROUP BY 1 ORDER BY 2 DESC LIMIT 20", [start, end, o])
            .map { ["country": $0[0].string ?? "", "bytes": "\($0[1].int64 ?? 0)", "flows": "\($0[2].int64 ?? 0)"] as [String: String] }
        var alerts: [String: Int64] = [:]
        for r in try db.query("SELECT severity, COUNT(*) FROM alerts WHERE first_occurrence >= ? AND first_occurrence < ? AND origin = ? GROUP BY 1", [start, end, o]) { alerts["severity\(r[0].int64 ?? 0)"] = r[1].int64 ?? 0 }
        doc["alerts"] = alerts
        doc["denied"] = try db.scalar("SELECT COALESCE(SUM(denied), 0) FROM rollup_hour WHERE bucket >= ? AND bucket < ? AND origin = ?", [start, end, o]).int64 ?? 0
        let data = try JSONSerialization.data(withJSONObject: doc, options: [.sortedKeys])
        let json = String(decoding: data, as: UTF8.self)
        try db.run("INSERT OR REPLACE INTO daily_summary (day, origin, json) VALUES (?, ?, ?)", [start, o, json])
        return json
    }

    public func dailySummary(day: Timestamp, origin: Origin) throws -> String? {
        try db.scalar("SELECT json FROM daily_summary WHERE day = ? AND origin = ?", [day.truncated(to: Self.dayMicros), Int(origin.rawValue)]).string
    }

    /// Days (UTC) that have hour rollups but no summary yet, excluding the current day.
    public func daysNeedingSummary(origin: Origin, now: Timestamp) throws -> [Timestamp] {
        let today = now.truncated(to: Self.dayMicros)
        return try db.query("""
            SELECT DISTINCT (bucket / ?) * ? AS d FROM rollup_hour WHERE origin = ? AND bucket < ?
              AND NOT EXISTS (SELECT 1 FROM daily_summary s WHERE s.day = (rollup_hour.bucket / ?) * ? AND s.origin = rollup_hour.origin)
            ORDER BY d LIMIT 31
            """, [Self.dayMicros, Self.dayMicros, Int(origin.rawValue), today, Self.dayMicros, Self.dayMicros]).map { Timestamp(microseconds: $0[0].int64 ?? 0) }
    }
}
