import XCTest
@testable import NetSentryExport
import NetSentryAnalytics
import NetSentryCore
@testable import NetSentryCorrelation
@testable import NetSentryDetection

final class ExportTests: XCTestCase {
    private let t0 = NetSentryCore.Timestamp(seconds: 1_789_000_000)
    private func flow(_ i: Int) -> FlowRecord {
        var f = FlowRecord(exporter: ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0), exportSequence: UInt32(i), receivedAt: t0, exportTime: t0, startTime: t0, endTime: t0 + .seconds(1),
                           srcIP: IPAddress("192.168.99.31")!, dstIP: IPAddress("203.0.113.9")!)
        f.id = Int64(i); f.dstPort = 443; f.protocolNumber = 6; f.octets = 1234; f.packets = 5
        f.enrichment.direction = .outbound; f.enrichment.srcInternal = true; f.enrichment.dstCountry = "DE"; f.enrichment.service = "https"
        return f
    }
    private func event() -> SyslogEvent {
        var e = SyslogEvent(receivedAt: t0, sourceIP: IPAddress("192.168.99.1")!, transport: .udp, message: "denied 192.168.99.31 -> 203.0.113.9, \"quoted\"", raw: "<4>raw line 192.168.99.31")
        e.eventType = .firewall; e.srcIP = IPAddress("192.168.99.31"); e.dstIP = IPAddress("203.0.113.9"); e.dstPort = 22; e.deviceID = "aa:bb:cc:dd:ee:ff"; e.hostname = "UCG-Fiber"; e.username = "mitra"
        e.enrichment.srcInternal = true
        return e
    }
    private func isInternal(_ ip: IPAddress) -> Bool { ip.isPrivate }

    func testCSVEscapesAndCarriesEveryColumn() {
        let csv = RecordExport.flowsCSV([flow(1), flow(2)], policy: .none)
        let lines = csv.split(separator: "\n")
        XCTAssertEqual(lines.count, 3)
        XCTAssertEqual(lines[0].split(separator: ",").count, ExportedFlow.csvHeader.count)
        XCTAssertTrue(lines[1].hasPrefix("1,2026-09-10T"))
        XCTAssertTrue(lines[1].contains("192.168.99.31,0,203.0.113.9,443,6,TCP,5,1234,outbound,https"))
        let ecsv = RecordExport.eventsCSV([event()], policy: .none, isInternal: isInternal)
        XCTAssertTrue(ecsv.contains("\"denied 192.168.99.31 -> 203.0.113.9, \"\"quoted\"\"\""), "commas and quotes are escaped")
        XCTAssertTrue(ecsv.contains("aa:bb:cc:dd:ee:ff") && ecsv.contains("<4>raw line"))
    }

    func testSharingPolicyHashesInternalAddressesConsistentlyAndDropsIdentifiers() throws {
        let policy = RedactionPolicy.sharing
        let csv = RecordExport.flowsCSV([flow(1), flow(2)], policy: policy)
        XCTAssertFalse(csv.contains("192.168.99.31"))
        XCTAssertTrue(csv.contains("203.0.113.9"), "external addresses stay unless requested")
        let tokens = csv.split(separator: "\n").dropFirst().map { $0.split(separator: ",")[3] }
        XCTAssertEqual(tokens[0], tokens[1]); XCTAssertTrue(tokens[0].hasPrefix("ip-"))
        let other = RecordExport.flowsCSV([flow(1)], policy: RedactionPolicy(hashInternalAddresses: true, salt: "different"))
        XCTAssertNotEqual(other.split(separator: "\n").last!.split(separator: ",")[3], tokens[0], "a different salt yields different tokens")
        let ejson = String(decoding: try RecordExport.eventsJSON([event()], policy: policy, isInternal: isInternal), as: UTF8.self)
        XCTAssertFalse(ejson.contains("aa:bb:cc")); XCTAssertFalse(ejson.contains("raw line")); XCTAssertFalse(ejson.contains("mitra")); XCTAssertFalse(ejson.contains("UCG-Fiber"))
        XCTAssertFalse(ejson.contains("192.168.99.31"), "addresses inside free text are hashed too")
        XCTAssertTrue(ejson.contains("203.0.113.9"))
    }

    func testIncidentReportAndBundle() throws {
        let alert = Alert(id: 7, ruleName: "repeated-denials", ruleVersion: 1, severity: .medium, state: .open, title: "NAS denied 10 times from 203.0.113.9", summary: "s", explanation: "**Why:** 192.168.99.31 was denied",
                          createdAt: t0, updatedAt: t0, firstOccurrence: t0, lastOccurrence: t0, occurrenceCount: 3, dedupeKey: "k", clientID: 7, entity: .init(kind: "ip", id: "203.0.113.9", label: "203.0.113.9"),
                          evidence: ["destination": "203.0.113.9", "source": "192.168.99.31"], baseline: nil, flowIDs: [1], eventIDs: [], steps: ["Check the firewall rule"], resolvedAt: nil, origin: .live,
                          notes: [AlertNote(id: 1, createdAt: t0, text: "looked at it")])
        let entry = TimelineEntry(id: "f1", time: t0, endTime: nil, kind: .flow, title: "192.168.99.31 → 203.0.113.9:443", detail: "1 KB", relations: ["same client"], flow: flow(1), event: nil, alertID: nil, gap: nil, isAnchor: true)
        let inv = Investigation(request: InvestigationRequest(anchor: .address(IPAddress("203.0.113.9")!), range: TimeRange(start: t0, end: t0 + .seconds(60))), entries: [entry], truncated: false, elapsed: .zero)
        let md = IncidentExport.markdown(alert: alert, clientLabel: "nas", investigation: inv, policy: .sharing, isInternal: isInternal)
        XCTAssertTrue(md.contains("# Incident report"))
        XCTAssertTrue(md.contains("[note removed]")); XCTAssertFalse(md.contains("192.168.99.31")); XCTAssertTrue(md.contains("ip-"))
        XCTAssertTrue(md.contains("do not assert causation"))
        let bundle = try IncidentExport.bundle(inv, alert: alert, policy: .none, isInternal: isInternal)
        let obj = try JSONSerialization.jsonObject(with: bundle) as! [String: Any]
        XCTAssertEqual(obj["format"] as? String, "netsentry-investigation/1")
        XCTAssertEqual((obj["entries"] as! [[String: Any]]).count, 1)
        XCTAssertNotNil((obj["entries"] as! [[String: Any]])[0]["flow"])
        XCTAssertEqual(((obj["alert"] as! [String: Any])["notes"] as! [String]).count, 1)
    }
}
