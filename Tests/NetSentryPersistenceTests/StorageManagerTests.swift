import XCTest
@testable import NetSentryPersistence
import NetSentryCore
import NetSentryDevTools
import DuckDB

final class StorageManagerTests: XCTestCase {
    private func tempRoot() -> URL {
        let u = FileManager.default.temporaryDirectory.appending(path: "netsentry-store-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: u) }
        return u
    }

    private func dayDir(_ t: NetSentryCore.Timestamp, kind: String = "flows") -> String {
        var cal = Calendar(identifier: .gregorian); cal.timeZone = TimeZone(identifier: "UTC")!
        let c = cal.dateComponents([.year, .month, .day], from: t.date)
        return String(format: "%@/%04d/%02d/%02d", kind, c.year!, c.month!, c.day!)
    }

    private func makeFlows(_ n: Int, start: NetSentryCore.Timestamp, seed: UInt64 = 1) -> [FlowRecord] {
        var rng = SplitMix64(seed: seed)
        let exporter = ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0)
        return (0..<n).map { i in
            let t = NetSentryCore.Timestamp(microseconds: start.microseconds + Int64(i) * 1_000_000)
            var f = FlowRecord(exporter: exporter, exportSequence: UInt32(i), receivedAt: t, exportTime: t, startTime: t, endTime: t + .seconds(2),
                               srcIP: IPAddress(v4: 0xC0A8_630A + UInt32(i % 20)), dstIP: IPAddress(v4: 0xCB00_7100 + UInt32(rng.next() % 200)))
            f.srcPort = UInt16(40000 + i % 1000); f.dstPort = 443; f.protocolNumber = 6; f.packets = 3 + UInt64(i % 7); f.octets = 400 + UInt64(i % 900)
            f.enrichment.direction = .outbound; f.enrichment.srcInternal = true
            f.extraElements = [RawInformationElement(enterpriseNumber: 0, elementID: 256, value: Data([8, 0]))]
            return f
        }
    }

    private func makeEvents(_ n: Int, start: NetSentryCore.Timestamp) -> [SyslogEvent] {
        (0..<n).map { i in
            let t = NetSentryCore.Timestamp(microseconds: start.microseconds + Int64(i) * 1_000_000)
            var e = SyslogEvent(receivedAt: t, sourceIP: IPAddress("192.168.99.1")!, transport: .udp, message: "msg \(i)", raw: "<4>Sep 10 19:35:23 gw kernel: [WAN-D-1]IN=eth4 OUT= SRC=203.0.113.\(i % 250) DST=192.168.99.1 PROTO=TCP SPT=1 DPT=22 msg \(i)")
            e.eventType = .firewall; e.action = .deny; e.srcIP = IPAddress("203.0.113.\(i % 250)"); e.dstIP = IPAddress("192.168.99.1"); e.parseStatus = .parsed
            e.attributes = ["fw.ttl": "53"]
            return e
        }
    }

    func testWriteFlushReadBackAndManifest() async throws {
        let root = tempRoot()
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000))
        let start = NetSentryCore.Timestamp(seconds: 1_789_000_000)
        var flows = makeFlows(1_000, start: start), events = makeEvents(200, start: start)
        try await sm.ingest(flows: &flows, events: &events, exporters: [flows[0].exporter: 7])
        XCTAssertTrue(flows.allSatisfy { $0.id > 0 }, "ids are assigned at staging time")
        XCTAssertEqual(Set(flows.map(\.id)).count, 1_000)
        await sm.flushAll()
        let segs = try await sm.meta.segments()
        XCTAssertEqual(segs.count, 2)
        let flowSeg = try XCTUnwrap(segs.first { $0.kind == .flows })
        XCTAssertEqual(flowSeg.rowCount, 1_000); XCTAssertEqual(flowSeg.tier, .minute); XCTAssertEqual(flowSeg.state, .finalized)
        XCTAssertEqual(flowSeg.start, start); XCTAssertGreaterThan(flowSeg.bytes, 1_000); XCTAssertNotNil(flowSeg.sha256)
        XCTAssertTrue(flowSeg.path.hasPrefix(dayDir(start) + "/flows_m_"), flowSeg.path)
        let file = root.appending(path: flowSeg.path)
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int, 0o600)
        // Read back with a fresh DuckDB connection (as the dashboard would).
        let reader = try DuckEngine(memoryLimit: "256MB", threads: 1)
        let count = try reader.scalarInt64("SELECT COUNT(*) FROM read_parquet(\(DuckEngine.literal(file.path))) WHERE dst_port = 443 AND direction = 1")
        XCTAssertEqual(count, 1_000)
        let extra = try reader.scalarString("SELECT ie_extra FROM read_parquet(\(DuckEngine.literal(file.path))) LIMIT 1")
        XCTAssertEqual(extra, "{\"0:256\":\"CAA=\"}", "unknown IEs survive as base64 JSON")
        let firstOctets = try reader.scalarInt64("SELECT octets::BIGINT FROM read_parquet(\(DuckEngine.literal(file.path))) ORDER BY flow_id LIMIT 1")
        XCTAssertEqual(firstOctets, 400)
        let eventSeg = try XCTUnwrap(segs.first { $0.kind == .events })
        XCTAssertEqual(eventSeg.rowCount, 200); XCTAssertGreaterThan(eventSeg.rawBytes, 0, "raw column bytes are accounted separately")
        let stats = try await sm.meta.segmentStats(id: flowSeg.id)
        XCTAssertEqual(stats.first { $0.column == "start_time" }?.min, start.microseconds)
        XCTAssertEqual(stats.first { $0.column == "dst_port" }?.max, 443)
        // Rollups
        let minutes = try sm.meta.db.scalar("SELECT COUNT(*) FROM rollup_minute").int64 ?? 0
        let expectedBuckets = Set(flows.map { $0.startTime.microseconds / 60_000_000 }).count
        XCTAssertEqual(minutes, Int64(expectedBuckets))
        let bytes = try sm.meta.db.scalar("SELECT SUM(bytes) FROM rollup_minute").int64 ?? 0
        XCTAssertEqual(bytes, Int64(flows.reduce(0) { $0 + $1.octets }))
        let hours = try sm.meta.db.scalar("SELECT COUNT(*) FROM rollup_hour").int64 ?? 0
        XCTAssertGreaterThan(hours, 0)
        let summary = await sm.summary()
        XCTAssertEqual(summary.segmentCount, 2); XCTAssertGreaterThan(summary.usedBytes, 0); XCTAssertEqual(summary.oldestRecord, start)
        XCTAssertFalse(summary.ingestionPaused)
    }

    func testRecoveryCleansTmpQuarantinesOrphansAndMarksMissing() async throws {
        let root = tempRoot()
        var sm: StorageManager? = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000))
        var flows = makeFlows(50, start: NetSentryCore.Timestamp(seconds: 1_789_000_000)), events: [SyslogEvent] = []
        try await sm!.ingest(flows: &flows, events: &events, exporters: [:])
        await sm!.flushAll()
        let seg = try await sm!.meta.segments(kind: .flows).first!
        sm = nil
        // Simulate: an interrupted write, an orphan file, and a deleted segment file.
        let fm = FileManager.default
        try fm.createDirectory(at: root.appending(path: "tmp"), withIntermediateDirectories: true)
        try Data("partial".utf8).write(to: root.appending(path: "tmp/flows_m_1_9.parquet.tmp"))
        let orphan = root.appending(path: dayDir(NetSentryCore.Timestamp(seconds: 1_789_000_000)) + "/flows_m_1_99.parquet")
        try Data("orphan".utf8).write(to: orphan)
        try fm.removeItem(at: root.appending(path: seg.path))
        let again = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000))
        let report = await again.recoveryReport
        XCTAssertTrue(report.contains { $0.hasPrefix("Removed interrupted write") }, "\(report)")
        XCTAssertTrue(report.contains { $0.hasPrefix("Quarantined orphan") }, "\(report)")
        XCTAssertTrue(report.contains { $0.hasPrefix("Segment missing") }, "\(report)")
        XCTAssertFalse(fm.fileExists(atPath: root.appending(path: "tmp/flows_m_1_9.parquet.tmp").path))
        XCTAssertFalse(fm.fileExists(atPath: orphan.path))
        let states = try await again.meta.segments(states: [.missing])
        XCTAssertEqual(states.count, 1)
        let visible = try await again.meta.segments()
        XCTAssertTrue(visible.isEmpty, "missing segments are excluded from queries")
    }

    func testBudgetEnforcementDeletesOldestButKeepsRollups() async throws {
        let root = tempRoot()
        let threshold: SafetyThreshold = { var t = SafetyThreshold(); t.mode = .fixed; t.fixedBytes = 1; return t }()
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000, safetyThreshold: threshold))
        var start = NetSentryCore.Timestamp(seconds: 1_789_000_000)
        for _ in 0..<12 {
            var flows = makeFlows(3_000, start: start, seed: UInt64(start.seconds)), events: [SyslogEvent] = []
            try await sm.ingest(flows: &flows, events: &events, exporters: [:])
            try await sm.flushAll()
            start = start + .seconds(3_600)
        }
        let full = try await sm.measureUsage()
        let all = try await sm.meta.segments()
        XCTAssertEqual(all.count, 12)
        // Shrink the budget so that roughly half of the detailed data must go (metadata is fixed overhead).
        let budget = full.metadata + full.other + (full.flows / 2)
        await sm.update(policy: .init(budgetBytes: budget, safetyThreshold: threshold))
        await sm.enforceBudget()
        let survivors = try await sm.meta.segments()
        let usage = try await sm.measureUsage()
        XCTAssertLessThanOrEqual(usage.total, budget, "retention keeps usage within budget; \(survivors.count) segments left, usage \(usage.total)")
        XCTAssertLessThan(survivors.count, 12, "oldest segments were deleted"); XCTAssertGreaterThan(survivors.count, 0, "newest segments survive")
        XCTAssertEqual(survivors.map(\.start), all.suffix(survivors.count).map(\.start), "survivors are exactly the newest segments")
        let rollups = try sm.meta.db.scalar("SELECT COUNT(DISTINCT bucket / 3600000000) FROM rollup_minute").int64 ?? 0
        XCTAssertGreaterThanOrEqual(rollups, 12, "minute rollups survive for every hour, including deleted ones")
        let deleted = try sm.meta.db.scalar("SELECT COUNT(*) FROM segments WHERE state = 'deleted'").int64 ?? 0
        XCTAssertEqual(Int(deleted), 12 - survivors.count)
        for s in survivors { XCTAssertTrue(FileManager.default.fileExists(atPath: root.appending(path: s.path).path)) }
        for s in all where !survivors.contains(where: { $0.id == s.id }) { XCTAssertFalse(FileManager.default.fileExists(atPath: root.appending(path: s.path).path)) }
    }

    func testRetentionPlanPreviewDoesNotDelete() async throws {
        let root = tempRoot()
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000, safetyThreshold: { var t = SafetyThreshold(); t.mode = .fixed; t.fixedBytes = 1; return t }()))
        var start = NetSentryCore.Timestamp(seconds: 1_789_000_000)
        for _ in 0..<4 {
            var flows = makeFlows(2_000, start: start), events = makeEvents(500, start: start)
            try await sm.ingest(flows: &flows, events: &events, exporters: [:]); try await sm.flushAll(); start = start + .seconds(3_600)
        }
        let before = try await sm.meta.segments().count
        let usageNow = try await sm.measureUsage()
        let budget = usageNow.metadata + usageNow.other + 150_000   // keeps roughly one segment
        let plan = try await sm.plan(budget: budget)
        XCTAssertGreaterThan(plan.steps.count, 0)
        XCTAssertTrue(plan.steps.contains { $0.stage == 5 && $0.segments > 0 })
        XCTAssertLessThan(plan.usageAfter, plan.usageBefore)
        XCTAssertLessThanOrEqual(plan.usageAfter, Int64(Double(budget) * 0.97) + 1)
        XCTAssertTrue(plan.removesRecentData, "segments newer than a day are affected, so the UI must warn")
        let afterPlan = try await sm.meta.segments().count
        XCTAssertEqual(afterPlan, before, "planning never deletes")
    }

    func testRawStrippingAndAggregationRewrite() async throws {
        let root = tempRoot()
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000))
        let start = NetSentryCore.Timestamp(seconds: 1_789_000_000)
        var flows = makeFlows(3_000, start: start), events = makeEvents(1_000, start: start)
        try await sm.ingest(flows: &flows, events: &events, exporters: [:]); try await sm.flushAll()
        let eventSeg = try await sm.meta.segments(kind: .events).first!
        try await sm.stripRaw(eventSeg)
        let stripped = try await sm.meta.segments(kind: .events).first!
        XCTAssertEqual(stripped.rowCount, 1_000); XCTAssertLessThan(stripped.bytes, eventSeg.bytes); XCTAssertLessThan(stripped.rawBytes, 200, "only null-column headers remain")
        let reader = try DuckEngine(memoryLimit: "256MB", threads: 1)
        XCTAssertEqual(try reader.scalarInt64("SELECT COUNT(*) FROM read_parquet(\(DuckEngine.literal(root.appending(path: stripped.path).path))) WHERE raw IS NULL"), 1_000)
        XCTAssertEqual(try reader.scalarString("SELECT message FROM read_parquet(\(DuckEngine.literal(root.appending(path: stripped.path).path))) ORDER BY event_id LIMIT 1"), "msg 0", "normalized fields survive")
        let flowSeg = try await sm.meta.segments(kind: .flows).first!
        try await sm.aggregate(flowSeg)
        let agg = try await sm.meta.segments(kind: .flows).first!
        XCTAssertTrue(agg.compacted); XCTAssertEqual(agg.tier, .day); XCTAssertLessThan(agg.rowCount, 3_000); XCTAssertLessThan(agg.bytes, flowSeg.bytes)
        let p = DuckEngine.literal(root.appending(path: agg.path).path)
        XCTAssertEqual(try reader.scalarInt64("SELECT SUM(octets)::BIGINT FROM read_parquet(\(p))"), Int64(flows.reduce(0) { $0 + $1.octets }), "byte totals are preserved")
        XCTAssertEqual(try reader.scalarInt64("SELECT SUM(flow_count)::BIGINT FROM read_parquet(\(p))"), 3_000)
    }

    func testCompactionMergesMinuteSegmentsIntoHours() async throws {
        let root = tempRoot()
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000))
        let hour = NetSentryCore.Timestamp(seconds: 1_789_002_000 - 1_789_002_000 % 3_600)
        var total = 0
        for m in 0..<5 {
            var flows = makeFlows(100, start: hour + .seconds(Int64(m) * 60)), events: [SyslogEvent] = []
            try await sm.ingest(flows: &flows, events: &events, exporters: [:]); try await sm.flushAll(); total += 100
        }
        let minuteCount = try await sm.meta.segments(kind: .flows).count
        XCTAssertEqual(minuteCount, 5)
        await sm.compact(now: hour + .seconds(3_600 + 600))
        let after = try await sm.meta.segments(kind: .flows)
        XCTAssertEqual(after.count, 1); XCTAssertEqual(after[0].tier, .hour); XCTAssertEqual(after[0].rowCount, Int64(total))
        let issues = await sm.verify()
        XCTAssertEqual(issues, [], "merged segment verifies clean")
        let files = try FileManager.default.contentsOfDirectory(at: root.appending(path: dayDir(hour)), includingPropertiesForKeys: nil)
        XCTAssertEqual(files.count, 1, "minute files are removed after the merge")
    }
}

final class DiskSafetyTests: XCTestCase {
    private func tempRoot() -> URL {
        let u = FileManager.default.temporaryDirectory.appending(path: "netsentry-disk-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: u) }
        return u
    }

    func testIngestionPausesBelowThresholdAndResumesWithHysteresis() async throws {
        let root = tempRoot()
        // A fixed threshold far above the volume's free space forces the pause path.
        var high = SafetyThreshold(); high.mode = .fixed; high.fixedBytes = Int64.max / 4
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000, safetyThreshold: high))
        let paused = await sm.ingestionPaused
        XCTAssertTrue(paused, "startup below threshold pauses immediately")
        let exporter = ExporterKey(address: IPAddress("10.0.0.1")!, observationDomain: 0)
        var flows = (0..<10).map { i -> FlowRecord in
            let t = NetSentryCore.Timestamp(seconds: 1_789_000_000 + Int64(i))
            return FlowRecord(exporter: exporter, exportSequence: 0, receivedAt: t, exportTime: t, startTime: t, endTime: t, srcIP: IPAddress(v4: 1), dstIP: IPAddress(v4: 2))
        }
        var events: [SyslogEvent] = []
        try await sm.ingest(flows: &flows, events: &events, exporters: [:])   // buffered, not written
        let staged = await sm.stagedRecords
        XCTAssertEqual(staged, 0, "nothing reaches the writer while paused")
        try await sm.flushAll()
        let segs = try await sm.meta.segments()
        XCTAssertTrue(segs.isEmpty)
        // Lower the threshold: the next tick resumes and the buffered records are staged.
        var low = SafetyThreshold(); low.mode = .fixed; low.fixedBytes = 1
        await sm.update(policy: .init(budgetBytes: 5_000_000_000, safetyThreshold: low))
        var f2: [FlowRecord] = [], e2: [SyslogEvent] = []
        try await sm.ingest(flows: &f2, events: &e2, exporters: [:])
        await sm.flushAll()
        let resumed = await sm.ingestionPaused
        XCTAssertFalse(resumed)
        let after = try await sm.meta.segments()
        XCTAssertEqual(after.first?.rowCount, 10, "records buffered during the pause are written once space returns")
    }
}
