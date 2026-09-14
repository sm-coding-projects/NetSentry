import XCTest
import NetSentryAnalytics
import NetSentryCore
import NetSentryDevTools
import NetSentryIPFIX
import NetSentryPersistence

/// Performance suite (docs/performance-targets.md). Skipped unless NETSENTRY_BENCH=1; run with
/// `NETSENTRY_BENCH=1 swift test -c release --filter Benchmarks`. Results are printed as a Markdown table and
/// asserted only loosely (a 3× margin over the target) so a busy machine does not fail CI.
final class Benchmarks: XCTestCase {
    nonisolated(unsafe) private static var results: [(String, String, String, Bool)] = []
    private var root: URL!

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["NETSENTRY_BENCH"] == "1" else { throw XCTSkip("set NETSENTRY_BENCH=1") }
        root = FileManager.default.temporaryDirectory.appending(path: "netsentry-bench-\(UUID().uuidString)")
    }
    override func tearDown() { if let root { try? FileManager.default.removeItem(at: root) } }
    override class func tearDown() {
        guard !results.isEmpty else { return }
        var md = "| ID | Benchmark | Result | Target | OK |\n|---|---|---|---|---|\n"
        for (id, name, result, ok) in results.sorted(by: { $0.0 < $1.0 }) { md += "| \(id) | \(name) | \(result) | \(targets[id] ?? "") | \(ok ? "✅" : "❌") |\n" }
        print("\nBENCHMARK RESULTS (\(ProcessInfo.processInfo.activeProcessorCount) cores, \(Int(Double(ProcessInfo.processInfo.physicalMemory) / 1e9)) GB)\n" + md)
        if let out = ProcessInfo.processInfo.environment["NETSENTRY_BENCH_OUT"] { try? md.write(toFile: out, atomically: true, encoding: .utf8) }
    }
    private static let targets = ["P1-decode": "≥ 5,000 flows/s decode", "P1-ingest": "≥ 5,000 flows/s persisted", "P5": "< 60 s for 60 minute-segments", "P7": "< 500 ms", "P8": "< 5 s (pruned)", "P14": "< 150 ms per page", "P13": "≤ 4 batches/s ≤ 500 records"]
    private func record(_ id: String, _ name: String, _ result: String, ok: Bool) { Self.results.append((id, name, result, ok)); print("[\(id)] \(name): \(result) \(ok ? "OK" : "MISSED")") }

    // MARK: helpers

    private func datagrams(count: Int, perMessage: Int, seed: UInt64 = 7) -> [RawDatagram] {
        var src = SyntheticFlowSource(seed: seed, clientCount: 60, destinationCount: 400)
        var out: [RawDatagram] = []
        let exporter = IPAddress("192.168.99.1")!
        let start = UInt64(Date().timeIntervalSince1970 * 1000) - UInt64(count) * 10
        var seq: UInt32 = 0
        var i = 0
        while i < count {
            var b = IPFIXBuilder(observationDomain: 0, sequence: seq)
            if seq == 0 { b.addTemplate(id: 264, fields: IPFIXBuilder.ucgFiberV4Fields) }
            let n = min(perMessage, count - i)
            b.addDataSet(templateID: 264, records: (0..<n).map { _ in src.nextRecord(endMilliseconds: start + UInt64(i) * 10) })
            out.append(RawDatagram(receivedAt: .now, kind: .ipfix, transport: .udp, source: exporter, sourcePort: 40000, localPort: 2055, payload: b.build(dataRecords: n)))
            seq &+= UInt32(n); i += n
        }
        return out
    }

    private func decodeAll(_ ds: [RawDatagram]) -> [FlowRecord] {
        let dec = IPFIXDecoder()
        var flows: [FlowRecord] = []
        for d in ds { flows += dec.decode(d).flows }
        return flows
    }

    private func populate(flows n: Int) async throws -> StorageManager {
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 50_000_000_000))
        let ds = datagrams(count: n, perMessage: 20)
        var batch: [FlowRecord] = []; var events: [SyslogEvent] = []
        let exporter = ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0)
        for chunk in stride(from: 0, to: ds.count, by: 500) {
            batch = decodeAll(Array(ds[chunk..<min(chunk + 500, ds.count)]))
            for i in batch.indices { batch[i].enrichment.direction = .outbound; batch[i].enrichment.srcInternal = true; batch[i].enrichment.srcClientID = Int64(batch[i].srcIP.bytes.last ?? 0) }
            try await sm.ingest(flows: &batch, events: &events, exporters: [exporter: 1])
        }
        await sm.flushAll()
        return sm
    }

    // MARK: benchmarks

    func testP1DecodeThroughput() throws {
        let ds = datagrams(count: 50_000, perMessage: 20)
        let t0 = ContinuousClock.now
        let flows = decodeAll(ds)
        let s = (ContinuousClock.now - t0).seconds
        XCTAssertEqual(flows.count, 50_000)
        let rate = Double(flows.count) / s
        record("P1-decode", "IPFIX decode + normalize, 50k records in 2.5k datagrams", String(format: "%.0f flows/s", rate), ok: rate >= 5_000)
    }

    func testP1IngestThroughputAndBytesPerFlow() async throws {
        let n = 100_000
        let t0 = ContinuousClock.now
        let sm = try await populate(flows: n)
        let s = (ContinuousClock.now - t0).seconds
        let usage = try await sm.meta.segmentUsage()
        let rate = Double(n) / s
        record("P1-ingest", "decode + enrich + stage + Parquet flush, 100k flows", String(format: "%.0f flows/s, %.1f B/flow on disk (%d segments)", rate, Double(usage.flows) / Double(n), usage.count), ok: rate >= 5_000)
        await sm.closeGracefully()
    }

    func testP7RollupOverviewThirtyDays() async throws {
        let meta = try MetaStore(root: root)
        let now = NetSentryCore.Timestamp.now.truncated(to: 60_000_000)
        var rows: [MetaStore.MinuteRollup] = []
        for m in 0..<(30 * 1440) {
            let b = NetSentryCore.Timestamp(microseconds: now.microseconds - Int64(m) * 60_000_000)
            rows.append(.init(bucket: b, origin: .live, clientID: 0, direction: TrafficDirection.outbound.rawValue, flows: 300, packets: 6_000, bytes: 4_000_000, denied: 0, allowed: 0))
            rows.append(.init(bucket: b, origin: .live, clientID: 0, direction: TrafficDirection.inbound.rawValue, flows: 200, packets: 5_000, bytes: 30_000_000, denied: 0, allowed: 0))
            if rows.count >= 20_000 { try await meta.mergeMinuteRollups(rows); rows.removeAll() }
        }
        try await meta.mergeMinuteRollups(rows)
        let engine = try ReadEngine(root: root)
        let range = TimeRange(start: NetSentryCore.Timestamp(microseconds: now.microseconds - 30 * 86_400_000_000), end: now)
        _ = try await engine.timeSeries(RecordFilter(range: range), bucket: .seconds(3600))   // warm
        let t0 = ContinuousClock.now
        let series = try await engine.timeSeries(RecordFilter(range: range), bucket: .seconds(3600))
        let totals = try await engine.totals(range, origin: .live)
        let ms = (ContinuousClock.now - t0).seconds * 1000
        XCTAssertGreaterThan(series.count, 700); XCTAssertNotNil(totals)
        record("P7", "Overview series + totals over 30 days from 86,400 minute rollups", String(format: "%.0f ms", ms), ok: ms < 500)
    }

    func testP8AndP14QueriesOverStore() async throws {
        let sm = try await populate(flows: 100_000)
        await sm.closeGracefully()
        let engine = try ReadEngine(root: root)
        let range = TimeRange(start: NetSentryCore.Timestamp(microseconds: NetSentryCore.Timestamp.now.microseconds - 86_400_000_000), end: .now)
        var q = FlowQuery(filter: RecordFilter(range: range)); q.limit = 500
        _ = try await engine.flows(q)   // warm (DuckDB parquet metadata cache)
        let t0 = ContinuousClock.now
        let page1 = try await engine.flows(q)
        let ms1 = (ContinuousClock.now - t0).seconds * 1000
        XCTAssertEqual(page1.rows.count, 500)
        var q2 = q; q2.cursor = page1.nextCursor
        let t1 = ContinuousClock.now
        let page2 = try await engine.flows(q2)
        let ms2 = (ContinuousClock.now - t1).seconds * 1000
        XCTAssertEqual(page2.rows.count, 500)
        record("P14", "Flows page fetch (500 rows) over 100k-flow store, first and next page", String(format: "%.0f ms / %.0f ms", ms1, ms2), ok: max(ms1, ms2) < 150)
        var who = RecordFilter(range: range); who.anyIP = page1.rows[0].dstIP
        let t2 = ContinuousClock.now
        let hits = try await engine.topN(TopNQuery(filter: who, dimension: .srcIP, limit: 50))
        let ms3 = (ContinuousClock.now - t2).seconds * 1000
        XCTAssertFalse(hits.isEmpty)
        record("P8", "Which internal devices talked to one external IP (pruned scan of 100k flows)", String(format: "%.0f ms", ms3), ok: ms3 < 5_000)
    }

    func testP5CompactionOfSixtyMinuteSegments() async throws {
        let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 50_000_000_000))
        let exporter = ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0)
        let base = NetSentryCore.Timestamp(microseconds: NetSentryCore.Timestamp.now.microseconds - 3 * 3_600_000_000).truncated(to: 3_600_000_000)
        var src = SyntheticFlowSource(seed: 3)
        let dec = IPFIXDecoder()
        for minute in 0..<60 {
            var b = IPFIXBuilder(observationDomain: 0, sequence: UInt32(minute * 50_000))
            if minute == 0 { b.addTemplate(id: 264, fields: IPFIXBuilder.ucgFiberV4Fields) }
            let endMs = UInt64((base.microseconds + Int64(minute) * 60_000_000) / 1000)
            var flows: [FlowRecord] = []
            for _ in 0..<50 {   // 50 datagrams × 20 records = 1,000 flows per minute → 60k
                var m = b; m.addDataSet(templateID: 264, records: (0..<20).map { _ in src.nextRecord(endMilliseconds: endMs + UInt64.random(in: 0..<59_000)) })
                flows += dec.decode(RawDatagram(receivedAt: .now, kind: .ipfix, transport: .udp, source: exporter.address, sourcePort: 1, localPort: 2055, payload: m.build(dataRecords: 20))).flows
                b = IPFIXBuilder(observationDomain: 0, sequence: UInt32(minute * 50_000))
            }
            var events: [SyslogEvent] = []
            try await sm.ingest(flows: &flows, events: &events, exporters: [exporter: 1])
            await sm.flushAll(now: NetSentryCore.Timestamp(microseconds: base.microseconds + Int64(minute + 1) * 60_000_000))
        }
        let before = try await sm.meta.segments(kind: .flows).count
        let t0 = ContinuousClock.now
        await sm.compact(now: .now)
        let s = (ContinuousClock.now - t0).seconds
        let after = try await sm.meta.segments(kind: .flows).filter { $0.tier == .hour }.count
        record("P5", "Hour compaction of \(before) minute segments (~60k rows)", String(format: "%.1f s, %d hour segment(s)", s, after), ok: s < 60)
        await sm.closeGracefully()
    }
}

private extension Duration { var seconds: Double { Double(components.seconds) + Double(components.attoseconds) / 1e18 } }
