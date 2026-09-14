import XCTest
@testable import NetSentryPersistence
import NetSentryCore

final class DayRollupTests: XCTestCase {
    func testDayTierAndDailySummaryFromHourRollups() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "netsentry-day-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let meta = try MetaStore(root: root)
        let day = NetSentryCore.Timestamp(seconds: 1_789_000_000).truncated(to: MetaStore.dayMicros)
        var hours: [MetaStore.HourRollup] = []
        for h in 0..<24 {
            let b = NetSentryCore.Timestamp(microseconds: day.microseconds + Int64(h) * 3_600_000_000)
            hours.append(MetaStore.HourRollup(bucket: b, origin: .live, clientID: 7, dstIP: "203.0.113.9", dstPort: 443, protocolNumber: 6, direction: TrafficDirection.outbound.rawValue, dstCountry: "DE", dstASN: 3320, flows: 10, bytes: 1_000, packets: 20, denied: 0))
            hours.append(MetaStore.HourRollup(bucket: b, origin: .live, clientID: 8, dstIP: "198.51.100.5", dstPort: 22, protocolNumber: 6, direction: TrafficDirection.outbound.rawValue, dstCountry: "US", dstASN: 15169, flows: 1, bytes: 50, packets: 2, denied: 1))
        }
        try await meta.mergeHourRollups(hours)
        try await meta.mergeMinuteRollups([MetaStore.MinuteRollup(bucket: day, origin: .live, clientID: 0, direction: TrafficDirection.outbound.rawValue, flows: 264, packets: 528, bytes: 25_200, denied: 0, allowed: 0),
                                           MetaStore.MinuteRollup(bucket: day, origin: .live, clientID: 7, direction: TrafficDirection.outbound.rawValue, flows: 240, packets: 480, bytes: 24_000, denied: 0, allowed: 0)])
        let n = try await meta.buildDayRollups(day: day + .seconds(3600), origin: .live)
        XCTAssertEqual(n, 2)
        let rows = try await meta.dayRollups(from: day, to: day, origin: .live)
        XCTAssertEqual(rows.first { $0.clientID == 7 }?.flows, 240); XCTAssertEqual(rows.first { $0.clientID == 7 }?.bytes, 24_000)
        XCTAssertEqual(rows.first { $0.clientID == 8 }?.denied, 24)
        // Rebuilding is idempotent.
        _ = try await meta.buildDayRollups(day: day, origin: .live)
        let again = try await meta.dayRollups(from: day, to: day, origin: .live); XCTAssertEqual(again.count, 2)
        let pending = try await meta.daysNeedingSummary(origin: .live, now: day + .seconds(2 * 86_400))
        XCTAssertEqual(pending, [day])
        let json = try await meta.buildDailySummary(day: day, origin: .live)
        let doc = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
        XCTAssertEqual((((doc["totals"] as? [String: Any])?["outbound"] as? [String: Any])?["bytes"] as? NSNumber)?.int64Value, 25_200)
        XCTAssertEqual(((doc["topClients"] as? [[String: Any]])?.first?["client"] as? NSNumber)?.int64Value, 7)
        XCTAssertEqual(((doc["topDestinations"] as? [[String: Any]])?.first?["ip"] as? String), "203.0.113.9")
        XCTAssertEqual((doc["denied"] as? NSNumber)?.int64Value, 24)
        let stored = try await meta.dailySummary(day: day, origin: .live); XCTAssertEqual(stored, json)
        let remaining = try await meta.daysNeedingSummary(origin: .live, now: day + .seconds(2 * 86_400)); XCTAssertEqual(remaining, [])
    }
}
