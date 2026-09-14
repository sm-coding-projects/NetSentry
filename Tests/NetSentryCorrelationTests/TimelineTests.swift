import XCTest
@testable import NetSentryCorrelation
import NetSentryAnalytics
import NetSentryCore
import NetSentryPersistence

final class TimelineTests: XCTestCase {
    private var root: URL!
    private let t0 = NetSentryCore.Timestamp(seconds: 1_788_998_400)
    private let exporter = ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0)

    override func setUp() async throws {
        root = FileManager.default.temporaryDirectory.appending(path: "netsentry-timeline-\(UUID().uuidString)")
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000))
        var flows: [FlowRecord] = []
        for i in 0..<50 {
            let t = t0 + .seconds(Int64(i) * 10)
            var f = FlowRecord(exporter: exporter, exportSequence: UInt32(i), receivedAt: t, exportTime: t, startTime: t, endTime: t + .seconds(1),
                               srcIP: IPAddress(i % 2 == 0 ? "192.168.99.31" : "192.168.99.40")!, dstIP: IPAddress(i % 5 == 0 ? "203.0.113.9" : "198.51.100.\(i)")!)
            f.dstPort = 443; f.protocolNumber = 6; f.octets = 1_000; f.packets = 5; f.enrichment.direction = .outbound; f.enrichment.srcInternal = true
            f.enrichment.srcClientID = i % 2 == 0 ? 7 : 8
            flows.append(f)
        }
        var events: [SyslogEvent] = (0..<10).map { i in
            let t = t0 + .seconds(Int64(i) * 50 + 5)
            var e = SyslogEvent(receivedAt: t, sourceIP: exporter.address, transport: .udp, message: "denied \(i)", raw: "raw")
            e.eventType = .firewall; e.action = .deny; e.srcIP = IPAddress("203.0.113.9"); e.dstIP = IPAddress("192.168.99.31"); e.dstPort = 22; e.ruleName = "WAN_LOCAL-D-4001"
            e.enrichment.dstClientID = 7
            return e
        }
        try await sm.ingest(flows: &flows, events: &events, exporters: [exporter: 1])
        try await sm.flushAll()
        try await sm.meta.db.run("INSERT INTO annotations (ts, kind, title, text, created_at) VALUES (?, 'note', 'Maintenance window', 'NAS firmware update', ?)", [t0 + .seconds(100), t0])
        _ = try await sm.meta.openGap(kind: .sleep, reason: "Mac asleep", at: t0 + .seconds(200))
        try await sm.meta.closeAllOpenGaps(at: t0 + .seconds(260))
        try await sm.meta.db.run("INSERT INTO alerts (rule_name, rule_version, severity, state, title, summary, explanation_md, created_at, updated_at, first_occurrence, last_occurrence, dedupe_key, client_id, entity_json, evidence_json, refs_json, steps_json) VALUES ('repeated-denials', 1, 2, 'open', 'NAS denied 10 times', 's', 'e', ?, ?, ?, ?, 'k', 7, '{\"kind\":\"ip\",\"id\":\"203.0.113.9\",\"label\":\"203.0.113.9\"}', '{}', '{\"flows\":[],\"events\":[]}', '[]')", [t0, t0, t0 + .seconds(300), t0 + .seconds(455)])
        await sm.closeGracefully()
    }
    override func tearDown() { try? FileManager.default.removeItem(at: root) }

    func testClientAnchoredTimelineCombinesEverySourceWithExplicitRelations() async throws {
        let engine = try ReadEngine(root: root)
        let builder = TimelineBuilder(engine: engine, meta: try MetaStore(root: root, readOnly: true))
        let range = TimeRange(start: t0, end: t0 + .seconds(600))
        let inv = try await builder.build(InvestigationRequest(anchor: .client(7, label: "NAS", addresses: ["192.168.99.31"]), range: range))
        let kinds = Dictionary(grouping: inv.entries, by: \.kind).mapValues(\.count)
        XCTAssertEqual(kinds[.flow], 25, "only the anchored client's flows")
        XCTAssertEqual(kinds[.firewall], 10)
        XCTAssertEqual(kinds[.annotation], 1); XCTAssertEqual(kinds[.gap], 1); XCTAssertEqual(kinds[.alert], 1)
        XCTAssertTrue(zip(inv.entries, inv.entries.dropFirst()).allSatisfy { $0.time <= $1.time }, "chronological")
        XCTAssertTrue(inv.entries.filter { $0.kind == .flow }.allSatisfy { $0.relations.contains("same client") })
        XCTAssertTrue(inv.entries.first { $0.kind == .gap }!.detail.contains("absence of activity is not evidence"))
        XCTAssertFalse(inv.truncated)
    }

    func testFlowAnchoredTimelineMarksAnchorAndTemporalProximity() async throws {
        let engine = try ReadEngine(root: root)
        let meta = try MetaStore(root: root, readOnly: true)
        var q = FlowQuery(filter: RecordFilter(range: TimeRange(start: t0, end: t0 + .seconds(600)))); q.limit = 1; q.direction = .ascending
        q.filter.dstIP = IPAddress("203.0.113.9")
        let anchor = try await engine.flows(q).rows[0]
        let builder = TimelineBuilder(engine: engine, meta: meta)
        let inv = try await builder.build(InvestigationRequest(anchor: .flow(anchor), range: TimeRange(start: anchor.startTime + .seconds(-30), end: anchor.startTime + .seconds(30))))
        XCTAssertEqual(inv.entries.filter(\.isAnchor).count, 1)
        let near = inv.entries.filter { $0.relations.contains { $0.hasPrefix("within") } }
        XCTAssertFalse(near.isEmpty)
        let withAddress = inv.entries.filter { $0.relations.contains { $0.hasPrefix("same address") } }
        XCTAssertFalse(withAddress.isEmpty, "the denied events share 203.0.113.9 / 192.168.99.31 with the anchor")
        XCTAssertFalse(inv.entries.contains { $0.detail.lowercased().contains("caused") }, "no causal language")
    }

    func testAddressAndRangeAnchors() async throws {
        let engine = try ReadEngine(root: root)
        let builder = TimelineBuilder(engine: engine, meta: try MetaStore(root: root, readOnly: true))
        let range = TimeRange(start: t0, end: t0 + .seconds(600))
        let byAddress = try await builder.build(InvestigationRequest(anchor: .address(IPAddress("203.0.113.9")!), range: range))
        XCTAssertEqual(byAddress.entries.filter { $0.kind == .flow }.count, 10)
        XCTAssertEqual(byAddress.entries.filter { $0.kind == .firewall }.count, 10)
        let all = try await builder.build(InvestigationRequest(anchor: .timeRange, range: range))
        XCTAssertEqual(all.entries.filter { $0.kind == .flow }.count, 50)
        XCTAssertEqual(all.entries.filter { $0.kind == .alert }.count, 1)
    }
}
