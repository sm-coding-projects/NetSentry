import XCTest
@testable import NetSentryAnalytics
import NetSentryCore
import NetSentryPersistence
import NetSentryDevTools

final class ReadEngineTests: XCTestCase {
    private var root: URL!
    private let t0 = NetSentryCore.Timestamp(seconds: 1_788_998_400)   // hour-aligned
    private let exporter = ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0)

    override func setUp() async throws {
        root = FileManager.default.temporaryDirectory.appending(path: "netsentry-analytics-\(UUID().uuidString)")
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000))
        // Three hourly segments: 600 flows each (10 clients × 60), plus events; distinct destinations per hour so pruning is testable.
        for h in 0..<3 {
            var flows: [FlowRecord] = []
            for i in 0..<600 {
                let t = NetSentryCore.Timestamp(microseconds: t0.microseconds + Int64(h) * 3_600_000_000 + Int64(i) * 5_000_000)
                var f = FlowRecord(exporter: exporter, exportSequence: UInt32(i), receivedAt: t, exportTime: t, startTime: t, endTime: t + .seconds(1),
                                   srcIP: IPAddress(v4: 0xC0A8_630A + UInt32(i % 10)), dstIP: IPAddress(v4: 0xCB00_7100 + UInt32(h * 50 + i % 50)))
                f.srcPort = 40_000 + UInt16(i); f.dstPort = i % 3 == 0 ? 53 : 443; f.protocolNumber = i % 3 == 0 ? 17 : 6
                f.packets = 10; f.octets = UInt64(1_000 + i); f.enrichment.direction = i % 4 == 0 ? .inbound : .outbound
                f.enrichment.dstCountry = i % 2 == 0 ? "US" : "DE"
                if i % 4 == 0 { swap(&f.srcIP, &f.dstIP) }
                flows.append(f)
            }
            var events: [SyslogEvent] = (0..<100).map { i in
                let t = NetSentryCore.Timestamp(microseconds: t0.microseconds + Int64(h) * 3_600_000_000 + Int64(i) * 30_000_000)
                var e = SyslogEvent(receivedAt: t, sourceIP: exporter.address, transport: .udp, message: i % 5 == 0 ? "Failed password for root" : "kernel line \(i)", raw: "raw \(i)")
                e.eventType = i % 5 == 0 ? .auth : .firewall; e.severity = i % 5 == 0 ? .warning : .informational
                e.action = i % 5 == 0 ? nil : .deny; e.srcIP = IPAddress(v4: 0xCB00_7100 + UInt32(i)); e.dstIP = IPAddress(v4: 0xC0A8_6301)
                e.ruleName = "WAN_LOCAL-D-\(4000 + i % 3)"
                return e
            }
            try await sm.ingest(flows: &flows, events: &events, exporters: [exporter: 1])
            try await sm.flushAll()
        }
        await sm.closeGracefully()
    }

    override func tearDown() { try? FileManager.default.removeItem(at: root) }

    /// Range covering `hours` whole hours (end is the last microsecond of the last hour, so the next hour's first flow is excluded).
    private func filter(hours: Int = 3) -> RecordFilter {
        RecordFilter(range: TimeRange(start: t0, end: NetSentryCore.Timestamp(microseconds: t0.microseconds + Int64(hours) * 3_600_000_000 - 1)))
    }

    func testFlowQueryFiltersAndKeysetPagination() async throws {
        let engine = try ReadEngine(root: root)
        var q = FlowQuery(filter: filter())
        q.filter.anyIP = IPAddress("192.168.99.12")
        q.limit = 100
        var page = try await engine.flows(q)
        XCTAssertEqual(page.rows.count, 100); XCTAssertNotNil(page.nextCursor); XCTAssertEqual(page.segmentsScanned, 3)
        XCTAssertTrue(page.rows.allSatisfy { $0.srcIP.description == "192.168.99.12" || $0.dstIP.description == "192.168.99.12" })
        XCTAssertTrue(zip(page.rows, page.rows.dropFirst()).allSatisfy { $0.startTime >= $1.startTime }, "descending by start time")
        var seen = Set(page.rows.map(\.id))
        while let c = page.nextCursor {
            q.cursor = c
            page = try await engine.flows(q)
            for r in page.rows { XCTAssertTrue(seen.insert(r.id).inserted, "keyset pagination never repeats a row") }
        }
        XCTAssertEqual(seen.count, 180, "client .12 appears in 60 flows per hour")
        // Port + protocol + direction + country filters
        var q2 = FlowQuery(filter: filter(hours: 1)); q2.filter.ports = [53]; q2.filter.protocols = [17]; q2.limit = 1_000
        let dns = try await engine.flows(q2)
        XCTAssertEqual(dns.rows.count, 200); XCTAssertTrue(dns.rows.allSatisfy { $0.dstPort == 53 && $0.protocolNumber == 17 })
        var q3 = FlowQuery(filter: filter()); q3.filter.directions = [.inbound]; q3.filter.countries = ["US"]; q3.limit = 10_000
        let inboundUS = try await engine.flows(q3)
        XCTAssertEqual(inboundUS.rows.count, 450)
        var q4 = FlowQuery(filter: filter()); q4.filter.prefix = IPPrefix("203.0.113.0/24"); q4.filter.minOctets = 1_500; q4.limit = 10_000
        let big = try await engine.flows(q4)
        XCTAssertEqual(big.rows.count, 300); XCTAssertTrue(big.rows.allSatisfy { $0.octets >= 1_500 })
        // Round-trip fidelity
        let f = big.rows[0]
        XCTAssertEqual(f.exporter, exporter); XCTAssertEqual(f.packets, 10); XCTAssertEqual(f.enrichment.dstCountry != nil, true); XCTAssertGreaterThan(f.id, 0)
    }

    func testSegmentPruningByStatistics() async throws {
        let engine = try ReadEngine(root: root)
        // Destination 203.0.113.60 only exists in hour 1 (h*50 + i%50 → 50…99).
        var f = filter(); f.dstIP = IPAddress("203.0.113.60")
        let segs = try await engine.candidateSegments(kind: .flows, filter: f)
        XCTAssertEqual(segs.count, 2, "dst_v4 min/max statistics prune hour 0 (max 203.0.113.49); hour 2's range still spans .60")
        var g = filter(hours: 1)
        let byTime = try await engine.candidateSegments(kind: .flows, filter: g)
        XCTAssertEqual(byTime.count, 1)
        g.ports = [8080]
        let noPort = try await engine.candidateSegments(kind: .flows, filter: g)
        XCTAssertEqual(noPort.count, 0, "no segment has that port range")
    }

    func testEventQueriesAndCounts() async throws {
        let engine = try ReadEngine(root: root)
        var q = EventQuery(filter: filter()); q.filter.eventTypes = [.auth]; q.limit = 1_000
        let auth = try await engine.events(q)
        XCTAssertEqual(auth.rows.count, 60); XCTAssertTrue(auth.rows.allSatisfy { $0.eventType == .auth && $0.severity == .warning })
        var t = EventQuery(filter: filter()); t.filter.text = "password"; t.limit = 1_000
        let pw = try await engine.events(t)
        XCTAssertEqual(pw.rows.count, 60)
        var d = EventQuery(filter: filter()); d.filter.actions = [.deny]; d.filter.severities = [.informational]; d.limit = 10
        let denied = try await engine.events(d)
        XCTAssertEqual(denied.rows.count, 10); XCTAssertNotNil(denied.nextCursor); XCTAssertEqual(denied.rows[0].raw?.hasPrefix("raw "), true)
        let byRule = try await engine.eventCounts(filter(), by: "rule_name")
        XCTAssertEqual(byRule.count, 3); XCTAssertEqual(byRule.reduce(0) { $0 + $1.count }, 300)
        let byType = try await engine.eventCounts(filter(), by: "event_type")
        XCTAssertEqual(Set(byType.map(\.key)), ["1", "3"])
    }

    func testTopNAndTimeSeries() async throws {
        let engine = try ReadEngine(root: root)
        let top = try await engine.topN(TopNQuery(filter: filter(), dimension: .dstPort, limit: 5))
        XCTAssertEqual(top.map(\.key), ["443", "53"])
        XCTAssertEqual(top.reduce(0) { $0 + $1.flows }, 1_800)
        let clients = try await engine.topN(TopNQuery(filter: filter(), dimension: .srcIP, limit: 3))
        XCTAssertEqual(clients.count, 3); XCTAssertTrue(clients[0].bytes >= clients[1].bytes)
        // Rollup path (no record-level filters) and scan path must agree on totals.
        let fromRollups = try await engine.timeSeries(filter(), bucket: .seconds(3_600))
        var scanned = filter(); scanned.minOctets = 0
        let fromScan = try await engine.timeSeries(scanned, bucket: .seconds(3_600))
        XCTAssertEqual(fromRollups.count, 3); XCTAssertEqual(fromScan.count, 3)
        XCTAssertEqual(fromRollups.map(\.bytes), fromScan.map(\.bytes))
        XCTAssertEqual(fromRollups.map(\.flows), [600, 600, 600])
        XCTAssertEqual(fromRollups[0].inboundBytes + fromRollups[0].outboundBytes, fromRollups[0].bytes)
        let totals = try await engine.totals(filter().range)
        XCTAssertEqual(totals.flows, 1_800)
    }

    func testEmptyRangeYieldsEmptyResultsNotErrors() async throws {
        let engine = try ReadEngine(root: root)
        let far = RecordFilter(range: TimeRange(start: NetSentryCore.Timestamp(seconds: 1), end: NetSentryCore.Timestamp(seconds: 2)))
        let a = try await engine.flows(FlowQuery(filter: far)), b = try await engine.topN(TopNQuery(filter: far, dimension: .dstIP)), c = try await engine.timeSeries(far, bucket: .seconds(60))
        XCTAssertEqual(a.rows.count, 0); XCTAssertEqual(b.count, 0); XCTAssertEqual(c.count, 0)
    }

    func testMaliciousTextIsBoundNotInterpolated() async throws {
        let engine = try ReadEngine(root: root)
        var q = EventQuery(filter: filter()); q.filter.text = "') OR 1=1 --"; q.limit = 10
        let inj = try await engine.events(q)
        XCTAssertEqual(inj.rows.count, 0)
        var f = FlowQuery(filter: filter()); f.filter.anyIP = IPAddress("203.0.113.60")
        let ok = try await engine.flows(f)
        XCTAssertGreaterThan(ok.rows.count, 0)
    }
}
