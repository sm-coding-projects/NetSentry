import XCTest
@testable import NetSentryIPC
import NetSentryCore

final class EnvelopeTests: XCTestCase {
    func testRequestEnvelopeRoundTrip() throws {
        let req = ListenerTestRequest(kind: .ipfix, seconds: 500)
        XCTAssertEqual(req.seconds, 120, "seconds are clamped")
        let data = try IPCCoding.envelope(for: req)
        let env = try IPCCoding.decode(IPCEnvelope.self, from: data)
        XCTAssertEqual(env.kind, ListenerTestRequest.kind)
        XCTAssertEqual(env.schemaVersion, IPCEnvelope.currentSchemaVersion)
        try IPCCoding.validate(env)
        let back = try IPCCoding.decode(ListenerTestRequest.self, from: env.payload)
        XCTAssertEqual(back.kind, .ipfix)
    }

    func testValidationRejectsWrongSchemaAndSize() throws {
        var env = IPCEnvelope(kind: "x", payload: Data())
        env.schemaVersion = 99
        XCTAssertThrowsError(try IPCCoding.validate(env))
        let big = IPCEnvelope(kind: "x", payload: Data(count: IPCEnvelope.maxPayloadBytes + 1))
        XCTAssertThrowsError(try IPCCoding.validate(big))
    }

    func testReplyCarriesError() throws {
        let r = IPCReply(requestID: UUID(), error: .unknownKind("nope"))
        let d = try IPCCoding.encode(r)
        let back = try IPCCoding.decode(IPCReply.self, from: d)
        XCTAssertEqual(back.error, .unknownKind("nope"))
        XCTAssertNil(back.payload)
    }

    func testHealthSnapshotRoundTrip() throws {
        let snap = HealthSnapshot(generatedAt: .now, collectorVersion: "0.1", collectorBuild: "1", startedAt: .now, pid: 1,
                                  listeners: [ListenerStatus(kind: .ipfix, transport: .udp, port: 4739, interface: nil, state: .failed("EADDRINUSE"))],
                                  exporters: [], counters: PipelineCounters(), rates: PipelineRates(), queues: [],
                                  openGaps: [CollectionGap(id: 1, start: .now, end: nil, kind: .sleep, reason: "zzz")],
                                  warnings: [], storage: nil, demoWorkspace: false)
        let d = try IPCCoding.encode(HealthChanged(snapshot: snap))
        let back = try IPCCoding.decode(HealthChanged.self, from: d)
        XCTAssertEqual(back.snapshot, snap)
    }
}
