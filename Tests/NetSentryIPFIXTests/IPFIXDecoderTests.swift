import XCTest
@testable import NetSentryIPFIX
import NetSentryCore
import NetSentryDevTools

final class IPFIXDecoderTests: XCTestCase {
    let exporterA = IPAddress("192.168.99.1")!
    let exporterB = IPAddress("192.168.99.2")!
    let t0 = Timestamp(seconds: 1_789_032_900)

    func datagram(_ payload: Data, from: IPAddress? = nil, at: Timestamp? = nil) -> RawDatagram {
        RawDatagram(receivedAt: at ?? t0, kind: .ipfix, transport: .udp, source: from ?? exporterA, sourcePort: 38531, localPort: 2055, payload: payload)
    }

    func ucgRecord(src: String, dst: String, sport: Int, dport: Int, pkts: Int, octets: Int, startMs: UInt64, endMs: UInt64, proto: Int = 6, selector: Int = 3) -> Data {
        IPFIXBuilder.encode(fields: IPFIXBuilder.ucgFiberV4Fields, values: [
            IPAddress(src)!, IPAddress(dst)!, IPAddress("192.168.99.1")!, UInt64(4), UInt64(sport), UInt64(dport), UInt64(0x1b), UInt64(5), UInt64(3),
            UInt64(pkts), UInt64(octets), startMs, endMs, UInt64(proto), UInt64(0), UInt64(1),
            Data([0x24, 0x5a, 0x4c, 0x11, 0x22, 0x33]), Data([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), UInt64(0x0800), UInt64(1), UInt64(selector),
        ])
    }

    func events<T>(_ r: IPFIXDecodeResult, _ match: (IPFIXEvent) -> T?) -> [T] { r.events.compactMap(match) }

    // MARK: Templates and records

    func testTemplateArrivalThenRecordsNormalize() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder(observationDomain: 0, sequence: 100, exportTime: UInt32(t0.seconds))
        b.addTemplate(id: 264, fields: IPFIXBuilder.ucgFiberV4Fields)
        let r1 = d.decode(datagram(b.build(dataRecords: 0)))
        XCTAssertEqual(events(r1) { if case .templateAdded(_, let id, let kind, let n) = $0 { return (id, kind, n) } else { return nil } }.map { "\($0.0)-\($0.1)-\($0.2)" }, ["264-data-21"])
        XCTAssertTrue(r1.flows.isEmpty)

        let start = UInt64(t0.milliseconds) - 5_000, end = UInt64(t0.milliseconds) - 1_000
        b.addDataSet(templateID: 264, records: [
            ucgRecord(src: "192.168.99.31", dst: "104.18.32.47", sport: 51000, dport: 443, pkts: 27, octets: 9307, startMs: start, endMs: end),
            ucgRecord(src: "104.18.32.47", dst: "192.168.99.31", sport: 443, dport: 51000, pkts: 20, octets: 40000, startMs: start, endMs: end, proto: 6),
        ], padding: 2)
        let r2 = d.decode(datagram(b.build(dataRecords: 2)))
        XCTAssertEqual(r2.flows.count, 2)
        XCTAssertEqual(r2.dataRecordCount, 2)
        let f = r2.flows[0]
        XCTAssertEqual(f.srcIP.description, "192.168.99.31"); XCTAssertEqual(f.dstIP.description, "104.18.32.47")
        XCTAssertEqual(f.srcPort, 51000); XCTAssertEqual(f.dstPort, 443); XCTAssertEqual(f.protocolNumber, 6)
        XCTAssertEqual(f.packets, 27); XCTAssertEqual(f.octets, 9307); XCTAssertEqual(f.tcpFlags, 0x1b)
        XCTAssertEqual(f.startTime.milliseconds, Int64(start)); XCTAssertEqual(f.endTime.milliseconds, Int64(end))
        XCTAssertEqual(f.ingressInterface, 5); XCTAssertEqual(f.egressInterface, 3); XCTAssertEqual(f.flowDirection, 1); XCTAssertEqual(f.flowEndReason, 1)
        XCTAssertEqual(f.exporter.observationDomain, 0); XCTAssertEqual(f.exportSequence, 100)
        // Unmapped elements (nextHop 15, ToS 5, MACs 80/56, ethernetType 256) are preserved, not discarded.
        XCTAssertEqual(Set(f.extraElements.map(\.elementID)), [15, 5, 80, 56, 256])
        XCTAssertEqual(f.extraElements.first { $0.elementID == 256 }?.value, Data([0x08, 0x00]))
        XCTAssertNil(f.samplingInterval, "no sampling info learned yet")
        XCTAssertEqual(d.exporter(f.exporter)?.records, 2)
    }

    func testTemplateRefreshReplacementAndWithdrawal() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder()
        b.addTemplate(id: 300, fields: [.init(8, 4), .init(12, 4)])
        _ = d.decode(datagram(b.build(dataRecords: 0)))
        b.addTemplate(id: 300, fields: [.init(8, 4), .init(12, 4)])
        let refreshed = d.decode(datagram(b.build(dataRecords: 0), at: t0 + .seconds(60)))
        XCTAssertEqual(events(refreshed) { if case .templateRefreshed(_, let id) = $0 { return id } else { return nil } }, [UInt16(300)])
        XCTAssertEqual(d.exporter(ExporterKey(address: exporterA, observationDomain: 1))?.templates[300]?.refreshCount, 1)
        b.addTemplate(id: 300, fields: [.init(8, 4), .init(12, 4), .init(7, 2)])
        let replaced = d.decode(datagram(b.build(dataRecords: 0)))
        XCTAssertEqual(events(replaced) { if case .templateReplaced(_, let id, let n) = $0 { return "\(id)-\(n)" } else { return nil } }, ["300-3"])
        // Records now decode with the new 10-byte layout.
        b.addDataSet(templateID: 300, records: [IPFIXBuilder.encode(fields: [.init(8, 4), .init(12, 4), .init(7, 2)], values: [IPAddress("10.0.0.1")!, IPAddress("10.0.0.2")!, 8080])])
        let r = d.decode(datagram(b.build(dataRecords: 1)))
        XCTAssertEqual(r.flows.first?.srcPort, 8080)
        b.addWithdrawal(id: 300)
        let w = d.decode(datagram(b.build(dataRecords: 0)))
        XCTAssertEqual(events(w) { if case .templateWithdrawn(_, let id) = $0 { return id } else { return nil } }, [UInt16(300)])
        b.addDataSet(templateID: 300, records: [Data(count: 10)])
        let m = d.decode(datagram(b.build(dataRecords: 1)))
        XCTAssertEqual(events(m) { if case .missingTemplate(_, let id, _, let buffered) = $0 { return "\(id)-\(buffered)" } else { return nil } }, ["300-true"])
    }

    func testDataBeforeTemplateIsBufferedThenDecoded() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder(observationDomain: 0, sequence: 359, exportTime: UInt32(t0.seconds))
        let fields: [IPFIXBuilder.Field] = [.init(8, 4), .init(12, 4), .init(11, 2)]
        let rec = IPFIXBuilder.encode(fields: fields, values: [IPAddress("192.168.99.5")!, IPAddress("1.1.1.1")!, 53])
        b.addDataSet(templateID: 259, records: [rec, rec])
        let r1 = d.decode(datagram(b.build(dataRecords: 2)))
        XCTAssertTrue(r1.flows.isEmpty)
        XCTAssertEqual(events(r1) { if case .missingTemplate(_, 259, let bytes, true) = $0 { return bytes } else { return nil } }, [20])
        XCTAssertEqual(d.exporter(ExporterKey(address: exporterA, observationDomain: 0))?.pendingSets, 1)
        b.addTemplate(id: 259, fields: fields)
        let r2 = d.decode(datagram(b.build(dataRecords: 0), at: t0 + .seconds(30)))
        XCTAssertEqual(r2.flows.count, 2)
        XCTAssertEqual(r2.flows[0].dstPort, 53)
        XCTAssertEqual(r2.flows[0].receivedAt, t0, "buffered records keep their original receive time")
        XCTAssertEqual(events(r2) { if case .pendingDecoded(_, 259, let n) = $0 { return n } else { return nil } }, [2])
        XCTAssertEqual(d.exporter(ExporterKey(address: exporterA, observationDomain: 0))?.pendingSets, 0)
    }

    func testPendingBufferIsBoundedAndExpires() {
        var limits = IPFIXDecoder.Limits(); limits.maxPendingSetsPerExporter = 2; limits.pendingTTL = .seconds(10)
        let d = IPFIXDecoder(limits: limits)
        var b = IPFIXBuilder()
        for _ in 0..<3 { b.addDataSet(templateID: 400, records: [Data(count: 8)]) }
        let r = d.decode(datagram(b.build(dataRecords: 3)))
        let buffered = events(r) { if case .missingTemplate(_, _, _, let buf) = $0 { return buf } else { return nil } }
        XCTAssertEqual(buffered, [true, true, false])
        b.addTemplate(id: 999, fields: [.init(1, 4)])
        let later = d.decode(datagram(b.build(dataRecords: 0), at: t0 + .seconds(20)))
        XCTAssertEqual(events(later) { if case .pendingDropped(_, 400, let n, _) = $0 { return n } else { return nil } }, [2])
    }

    func testEnterpriseAndVariableLengthFields() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder()
        let fields: [IPFIXBuilder.Field] = [.init(8, 4), .init(12, 4), .init(1, 4, pen: 4242), .init(96, 65535), .init(2, 4, pen: 29305), .init(95, 65535)]
        b.addTemplate(id: 500, fields: fields)
        let long = String(repeating: "x", count: 300)
        let rec = IPFIXBuilder.encode(fields: fields, values: [IPAddress("10.1.1.1")!, IPAddress("10.1.1.2")!, 77, "netflix", 999, Data(long.utf8)])
        b.addDataSet(templateID: 500, records: [rec, rec])
        let r = d.decode(datagram(b.build(dataRecords: 2)))
        XCTAssertEqual(r.flows.count, 2)
        let f = r.flows[0]
        XCTAssertEqual(f.reversePackets, 999)
        XCTAssertEqual(f.applicationID?.count, 600, "variable-length > 254 bytes uses the 3-byte length form; IE 95 renders as hex")
        XCTAssertEqual(f.extraElements.count, 1)
        XCTAssertEqual(f.extraElements[0].enterpriseNumber, 4242); XCTAssertEqual(f.extraElements[0].elementID, 1)
        XCTAssertEqual(f.extraElements[0].value, Data([0, 0, 0, 77]))
    }

    func testIPv6Records() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder()
        b.addTemplate(id: 265, fields: IPFIXBuilder.ipv6Fields)
        let ms = UInt64(t0.milliseconds)
        b.addDataSet(templateID: 265, records: [IPFIXBuilder.encode(fields: IPFIXBuilder.ipv6Fields, values: [
            IPAddress("2001:db8::10")!, IPAddress("2606:4700::6810:202f")!, 55000, 443, 6, 0x18, 12, 3400, ms - 100, ms])])
        let r = d.decode(datagram(b.build(dataRecords: 1)))
        XCTAssertEqual(r.flows.first?.srcIP.description, "2001:db8::10")
        XCTAssertEqual(r.flows.first?.dstIP.description, "2606:4700::6810:202f")
        XCTAssertEqual(r.flows.first?.ipVersion, 6)
        XCTAssertEqual(r.flows.first?.tcpFlags, 0x18)
    }

    // MARK: Options, sampling, exporter state

    func testOptionsTemplatesLearnSamplingDomainNameAndInterfaces() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder(observationDomain: 0)
        // UCG-style: 257 sampling per selector, 258 interface names, 256 system init + domain name.
        b.addOptionsTemplate(id: 257, scopeCount: 1, fields: [.init(149, 4), .init(302, 1), .init(390, 1), .init(309, 1), .init(310, 2)])
        b.addOptionsTemplate(id: 258, scopeCount: 1, fields: [.init(149, 4), .init(10, 2), .init(82, 16), .init(83, 32)])
        b.addOptionsTemplate(id: 256, scopeCount: 1, fields: [.init(149, 4), .init(160, 8), .init(300, 29), .init(152, 8), .init(153, 8)])
        b.addDataSet(templateID: 257, records: [IPFIXBuilder.encode(fields: [.init(149, 4), .init(302, 1), .init(390, 1), .init(309, 1), .init(310, 2)], values: [0, 3, 1, 1, 1000])])
        b.addDataSet(templateID: 258, records: [IPFIXBuilder.encode(fields: [.init(149, 4), .init(10, 2), .init(82, 16), .init(83, 32)], values: [0, 5, "br0", "LAN bridge"])])
        b.addDataSet(templateID: 256, records: [IPFIXBuilder.encode(fields: [.init(149, 4), .init(160, 8), .init(300, 29), .init(152, 8), .init(153, 8)],
                                                                    values: [0, UInt64(t0.milliseconds) - 86_400_000, "ucg-fiber", UInt64(t0.milliseconds), UInt64(t0.milliseconds)])])
        let r = d.decode(datagram(b.build(dataRecords: 3)))
        XCTAssertEqual(r.options.count, 3)
        let key = ExporterKey(address: exporterA, observationDomain: 0)
        let st = d.exporter(key)!
        XCTAssertEqual(st.sampling[3]?.rate, 1000)
        XCTAssertEqual(st.interfaceNames[5], "br0")
        XCTAssertEqual(st.observationDomainName, "ucg-fiber")
        XCTAssertNotNil(st.systemInitTime)
        XCTAssertTrue(r.events.contains { if case .samplingLearned = $0 { return true }; return false })
        XCTAssertTrue(r.events.contains { if case .interfaceName(_, 5, "br0", "LAN bridge") = $0 { return true }; return false })

        // Flows referencing selector 3 now carry the sampling rate; a changed init time flags a restart.
        b.addTemplate(id: 264, fields: IPFIXBuilder.ucgFiberV4Fields)
        b.addDataSet(templateID: 264, records: [ucgRecord(src: "192.168.99.31", dst: "1.1.1.1", sport: 1, dport: 53, pkts: 1, octets: 70, startMs: 1, endMs: 2, proto: 17, selector: 3)])
        XCTAssertEqual(d.decode(datagram(b.build(dataRecords: 1))).flows.first?.samplingInterval, 1000)
        b.addDataSet(templateID: 256, records: [IPFIXBuilder.encode(fields: [.init(149, 4), .init(160, 8), .init(300, 29), .init(152, 8), .init(153, 8)],
                                                                    values: [0, UInt64(t0.milliseconds), "ucg-fiber", UInt64(t0.milliseconds), UInt64(t0.milliseconds)])])
        let restart = d.decode(datagram(b.build(dataRecords: 1)))
        XCTAssertTrue(restart.events.contains { if case .exporterRestart = $0 { return true }; return false })
        XCTAssertEqual(d.exporter(key)?.restarts, 1)
    }

    func testSysUpTimeFallbackUsesSystemInitTime() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder(observationDomain: 0)
        b.addOptionsTemplate(id: 256, scopeCount: 1, fields: [.init(149, 4), .init(160, 8)])
        let initMs = UInt64(t0.milliseconds) - 1_000_000
        b.addDataSet(templateID: 256, records: [IPFIXBuilder.encode(fields: [.init(149, 4), .init(160, 8)], values: [0, initMs])])
        let f: [IPFIXBuilder.Field] = [.init(8, 4), .init(12, 4), .init(22, 4), .init(21, 4)]
        b.addTemplate(id: 300, fields: f)
        b.addDataSet(templateID: 300, records: [IPFIXBuilder.encode(fields: f, values: [IPAddress("10.0.0.1")!, IPAddress("10.0.0.2")!, 500_000, 600_000])])
        let r = d.decode(datagram(b.build(dataRecords: 2)))
        XCTAssertEqual(r.flows.first?.startTime.milliseconds, Int64(initMs + 500_000))
        XCTAssertEqual(r.flows.first?.endTime.milliseconds, Int64(initMs + 600_000))
    }

    func testSequenceGapsCountRecordsAndDetectRestart() {
        let d = IPFIXDecoder()
        let f: [IPFIXBuilder.Field] = [.init(8, 4), .init(12, 4)]
        let rec = IPFIXBuilder.encode(fields: f, values: [IPAddress("10.0.0.1")!, IPAddress("10.0.0.2")!])
        var b = IPFIXBuilder(sequence: 359)
        b.addTemplate(id: 300, fields: f)
        b.addDataSet(templateID: 300, records: [rec])
        _ = d.decode(datagram(b.build(dataRecords: 1)))                 // seq 359, 1 record → expect 360
        b.addDataSet(templateID: 300, records: [rec, rec, rec])
        let ok = d.decode(datagram(b.build(dataRecords: 3)))            // seq 360 ✓ → expect 363
        XCTAssertFalse(ok.events.contains { if case .sequenceGap = $0 { return true }; return false })
        b.sequence = 370                                                // 7 records lost
        b.addDataSet(templateID: 300, records: [rec])
        let gap = d.decode(datagram(b.build(dataRecords: 1)))
        XCTAssertEqual(events(gap) { if case .sequenceGap(_, let e, let r, let m) = $0 { return "\(e)/\(r)/\(m)" } else { return nil } }, ["363/370/7"])
        b.sequence = 2                                                  // exporter rebooted
        b.addDataSet(templateID: 300, records: [rec])
        let restart = d.decode(datagram(b.build(dataRecords: 1)))
        XCTAssertTrue(restart.events.contains { if case .exporterRestart(_, let why) = $0 { return why.contains("sequence reset") }; return false })
        XCTAssertEqual(d.exporter(ExporterKey(address: exporterA, observationDomain: 1))?.sequenceGaps, 1)
    }

    func testMultipleExportersAndDomainsAreIsolated() {
        let d = IPFIXDecoder()
        let f: [IPFIXBuilder.Field] = [.init(8, 4), .init(12, 4)]
        var a = IPFIXBuilder(observationDomain: 1), b2 = IPFIXBuilder(observationDomain: 1), a2 = IPFIXBuilder(observationDomain: 2)
        a.addTemplate(id: 300, fields: f)
        _ = d.decode(datagram(a.build(dataRecords: 0), from: exporterA))
        let rec = IPFIXBuilder.encode(fields: f, values: [IPAddress("10.0.0.1")!, IPAddress("10.0.0.2")!])
        b2.addDataSet(templateID: 300, records: [rec])
        XCTAssertTrue(d.decode(datagram(b2.build(dataRecords: 1), from: exporterB)).flows.isEmpty, "template from A must not apply to B")
        a2.addDataSet(templateID: 300, records: [rec])
        XCTAssertTrue(d.decode(datagram(a2.build(dataRecords: 1), from: exporterA)).flows.isEmpty, "template from domain 1 must not apply to domain 2")
        a.addDataSet(templateID: 300, records: [rec])
        XCTAssertEqual(d.decode(datagram(a.build(dataRecords: 1), from: exporterA)).flows.count, 1)
        XCTAssertEqual(d.exporters.count, 3)
    }

    func testTemplateExpiry() {
        var limits = IPFIXDecoder.Limits(); limits.templateLifetime = .seconds(100)
        let d = IPFIXDecoder(limits: limits)
        var b = IPFIXBuilder()
        b.addTemplate(id: 300, fields: [.init(8, 4)])
        _ = d.decode(datagram(b.build(dataRecords: 0)))
        XCTAssertEqual(d.expire(now: t0 + .seconds(50)).count, 0)
        let ev = d.expire(now: t0 + .seconds(200))
        XCTAssertEqual(events(IPFIXDecodeResult(events: ev)) { if case .templateExpired(_, let id) = $0 { return id } else { return nil } }, [UInt16(300)])
    }

    // MARK: Malformed input

    func testMalformedDatagramsNeverCrashAndAreReported() {
        let d = IPFIXDecoder()
        let cases: [(String, Data)] = [
            ("empty", Data()),
            ("one byte", Data([0])),
            ("netflow v9", Data([0, 9, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
            ("netflow v5", Data([0, 5, 0, 1]) + Data(count: 44)),
            ("header only, length 0", Data([0, 10, 0, 0]) + Data(count: 12)),
            ("length beyond datagram", Data([0, 10, 0xff, 0xff]) + Data(count: 12)),
            ("set length 3", Data([0, 10, 0, 20]) + Data(count: 12) + Data([1, 0, 0, 3])),
            ("set length beyond message", Data([0, 10, 0, 20]) + Data(count: 12) + Data([1, 4, 0, 200])),
            ("reserved set id", Data([0, 10, 0, 20]) + Data(count: 12) + Data([0, 5, 0, 4])),
            ("template with huge field count", Data([0, 10, 0, 24]) + Data(count: 12) + Data([0, 2, 0, 8, 1, 44, 0xff, 0xff])),
            ("template id below 256", Data([0, 10, 0, 28]) + Data(count: 12) + Data([0, 2, 0, 12, 0, 1, 0, 1, 0, 8, 0, 4])),
            ("options template zero scope", Data([0, 10, 0, 30]) + Data(count: 12) + Data([0, 3, 0, 14, 1, 44, 0, 1, 0, 0, 0, 8, 0, 4])),
            ("truncated template", Data([0, 10, 0, 26]) + Data(count: 12) + Data([0, 2, 0, 10, 1, 44, 0, 2, 0, 8])),
            ("enterprise flag without pen", Data([0, 10, 0, 28]) + Data(count: 12) + Data([0, 2, 0, 12, 1, 44, 0, 1, 0x80, 8, 0, 4])),
        ]
        for (name, bytes) in cases {
            let r = d.decode(datagram(bytes))
            XCTAssertTrue(r.flows.isEmpty, name)
            XCTAssertFalse(r.events.isEmpty, "\(name) must produce a diagnostic event")
        }
        // Version 9/5 are reported distinctly so the health view can tell the user to switch the gateway to IPFIX.
        let v9 = d.decode(datagram(Data([0, 9, 0, 20]) + Data(count: 16)))
        XCTAssertEqual(events(v9) { if case .unsupportedVersion(let v) = $0 { return v } else { return nil } }, [UInt16(9)])
    }

    func testZeroLengthRecordTemplateCannotLoopForever() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder()
        b.addTemplate(id: 300, fields: [.init(8, 0)])
        b.addDataSet(templateID: 300, records: [Data(count: 40)])
        let r = d.decode(datagram(b.build(dataRecords: 0)))
        XCTAssertTrue(r.flows.isEmpty)
        XCTAssertTrue(r.events.contains { if case .templateRejected(_, 300, let why) = $0 { return why.contains("zero-length") }; return false })
    }

    func testFuzzMutationsOfValidMessages() {
        let d = IPFIXDecoder()
        var b = IPFIXBuilder(observationDomain: 0, sequence: 1, exportTime: UInt32(t0.seconds))
        b.addTemplate(id: 264, fields: IPFIXBuilder.ucgFiberV4Fields)
        b.addOptionsTemplate(id: 257, scopeCount: 1, fields: [.init(149, 4), .init(302, 1), .init(390, 1), .init(309, 1), .init(310, 2)])
        b.addDataSet(templateID: 264, records: (0..<5).map { i in ucgRecord(src: "192.168.99.\(10 + i)", dst: "203.0.113.\(i)", sport: 40000 + i, dport: 443, pkts: 3, octets: 400, startMs: 1, endMs: 2) })
        let valid = b.build(dataRecords: 5)
        var rng = SplitMix64(seed: 7)
        var totalEvents = 0
        for _ in 0..<3_000 {
            var m = valid
            let mutations = 1 + Int(rng.next() % 4)
            for _ in 0..<mutations {
                let n = UInt64(max(m.count, 1))
                switch rng.next() % 4 {
                case 0: if !m.isEmpty { m[Int(rng.next() % n)] = UInt8(truncatingIfNeeded: rng.next()) }
                case 1: m = m.prefix(Int(rng.next() % n))
                case 2: m.insert(UInt8(truncatingIfNeeded: rng.next()), at: Int(rng.next() % (n + 1)) % (m.count + 1))
                default: m.append(contentsOf: Data((0..<Int(rng.next() % 64)).map { _ in UInt8(truncatingIfNeeded: rng.next()) }))
                }
            }
            let r = d.decode(datagram(m))
            totalEvents += r.events.count
            for f in r.flows { XCTAssertGreaterThanOrEqual(f.endTime, f.startTime) }
        }
        XCTAssertGreaterThan(totalEvents, 0)
    }

    // MARK: Real device captures (local only; Fixtures/incoming is git-ignored)

    func testRealCapturesDecodeWhenPresent() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let dir = root.appending(path: "Fixtures/incoming")
        let files = ((try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []).filter { $0.pathExtension == "nsraw" && $0.lastPathComponent.hasPrefix("ipfix") }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        try XCTSkipIf(files.isEmpty, "no real captures in Fixtures/incoming")
        let d = IPFIXDecoder()
        var flows = 0, options = 0, malformed = 0, missing = 0, pending = 0
        for f in files {
            for dg in RawCaptureFormat.decode(try Data(contentsOf: f)) {
                let r = d.decode(dg)
                flows += r.flows.count; options += r.options.count
                for e in r.events {
                    switch e {
                    case .exporterRestart(_, let why): print("real capture: restart event: \(why) at \(dg.receivedAt)")
                    case .malformed: malformed += 1
                    case .missingTemplate: missing += 1
                    case .pendingDecoded(_, _, let n): pending += n
                    default: break
                    }
                }
                for fl in r.flows {
                    XCTAssertNotEqual(fl.srcIP, IPAddress(v4: 0)); XCTAssertNotEqual(fl.dstIP, IPAddress(v4: 0))
                    XCTAssertGreaterThan(fl.octets, 0); XCTAssertGreaterThanOrEqual(fl.endTime, fl.startTime)
                    XCTAssertGreaterThan(fl.startTime, Timestamp(seconds: 1_700_000_000))
                }
            }
        }
        print("real capture: flows=\(flows) options=\(options) malformed=\(malformed) missingTemplate=\(missing) pendingDecoded=\(pending) exporters=\(d.exporters.map { "\($0.key) templates=\($0.templates.count) sampling=\($0.sampling) ifs=\($0.interfaceNames) restarts=\($0.restarts) gaps=\($0.sequenceGaps)" })")
        XCTAssertEqual(malformed, 0)
        XCTAssertGreaterThan(flows, 0)
    }
}

extension IPFIXDecodeResult { init(events: [IPFIXEvent]) { self.init(); self.events = events } }
