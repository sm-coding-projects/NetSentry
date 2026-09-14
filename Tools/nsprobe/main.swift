import Foundation
import NetSentryAnalytics
import NetSentryCore
import NetSentryDevTools
import NetSentryIPFIX
import NetSentryPersistence

/// Developer probe: exercises the write → flush → read path outside XCTest so it can run under sanitizers
/// (`swift run -c release -Xswiftc -sanitize=address nsprobe`). Prints a few counts and exits non-zero on error.
let root = FileManager.default.temporaryDirectory.appending(path: "netsentry-probe-\(UUID().uuidString)")
defer { try? FileManager.default.removeItem(at: root) }
let exporter = ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0)
let sm = try await StorageManager(root: root, policy: .init(budgetBytes: 5_000_000_000))
var src = SyntheticFlowSource(seed: 1)
let dec = IPFIXDecoder()
let batches = Int(ProcessInfo.processInfo.environment["NSPROBE_BATCHES"] ?? "3") ?? 3
let perBatch = Int(ProcessInfo.processInfo.environment["NSPROBE_PER_BATCH"] ?? "20") ?? 20
for batch in 0..<batches {
    var b = IPFIXBuilder(observationDomain: 0, sequence: UInt32(batch * 100))
    if batch == 0 { b.addTemplate(id: 264, fields: IPFIXBuilder.ucgFiberV4Fields) }
    let now = UInt64(Date().timeIntervalSince1970 * 1000)
    b.addDataSet(templateID: 264, records: (0..<perBatch).map { _ in src.nextRecord(endMilliseconds: now) })
    var flows = dec.decode(RawDatagram(receivedAt: .now, kind: .ipfix, transport: .udp, source: exporter.address, sourcePort: 1, localPort: 2055, payload: b.build(dataRecords: perBatch))).flows
    for i in flows.indices { flows[i].enrichment.direction = .outbound; flows[i].enrichment.srcInternal = true }
    var events: [SyslogEvent] = []
    try await sm.ingest(flows: &flows, events: &events, exporters: [exporter: 1])
    await sm.flushAll()
    if batch % 50 == 0 { print("batch \(batch): \(flows.count) flows flushed") }
}
await sm.closeGracefully()
let engine = try ReadEngine(root: root)
let range = TimeRange(start: Timestamp(microseconds: Timestamp.now.microseconds - 3_600_000_000), end: .now)
var q = FlowQuery(filter: RecordFilter(range: range)); q.limit = 500
_ = try await engine.flows(q)   // warm
func ms(_ d: Duration) -> String { String(format: "%.0f ms", Double(d.components.seconds) * 1000 + Double(d.components.attoseconds) / 1e15) }
var t = ContinuousClock.now
let page = try await engine.flows(q)
let first = ContinuousClock.now - t
var q2 = q; q2.cursor = page.nextCursor
t = ContinuousClock.now
let page2 = try await engine.flows(q2)
let second = ContinuousClock.now - t
t = ContinuousClock.now
let top = try await engine.topN(TopNQuery(filter: RecordFilter(range: range), dimension: .dstIP, limit: 5))
let topTime = ContinuousClock.now - t
let usage = try await engine.segmentCount()
print("read back \(page.rows.count) + \(page2.rows.count) rows; P14 page fetch \(ms(first)) / \(ms(second)); topN \(ms(topTime)); segments \(usage)")
