import XCTest
@testable import NetSentrySyslog
import NetSentryCore

final class SyslogParserTests: XCTestCase {
    let src = IPAddress("192.168.99.1")!
    let received = Timestamp(Date(timeIntervalSince1970: 1_789_061_723))   // 2026-09-10 17:35:23 UTC
    lazy var parser = SyslogParser(timeZone: TimeZone(identifier: "Europe/Berlin")!)

    func fixture(_ name: String) throws -> [String] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "txt", subdirectory: "syslog"))
        return try String(contentsOf: url, encoding: .utf8).split(separator: "\n").map(String.init).filter { !$0.hasPrefix("#") && !$0.isEmpty }
    }

    func parse(_ line: String, transport: Transport = .udp) -> SyslogEvent {
        parser.parse(RawDatagram(receivedAt: received, kind: .syslog, transport: transport, source: src, sourcePort: 514, localPort: 5514, payload: Data(line.utf8)))
    }

    func testRFC3164Header() throws {
        let lines = try fixture("rfc3164-generic")
        let e = parse(lines[0])
        XCTAssertEqual(e.facility, .user); XCTAssertEqual(e.severity, .informational); XCTAssertTrue(e.priorityPresent)
        XCTAssertEqual(e.hostname, "gateway"); XCTAssertEqual(e.appName, "kernel"); XCTAssertEqual(e.message, "sample message 1")
        XCTAssertEqual(e.syslogVersion, 0); XCTAssertTrue(e.timeInferred)
        XCTAssertEqual(e.eventTime?.date.timeIntervalSince1970, 1_789_061_723, "Sep 10 19:35:23 Berlin == 17:35:23 UTC, year inferred")
        XCTAssertEqual(e.raw, lines[0]); XCTAssertEqual(e.parseStatus, .partial)
        let ssh = parse(lines[1])
        XCTAssertEqual(ssh.facility, .auth); XCTAssertEqual(ssh.severity, .critical)
        XCTAssertEqual(ssh.appName, "sshd"); XCTAssertEqual(ssh.procID, "1234"); XCTAssertEqual(ssh.eventType, .auth)
        let cron = parse(lines[2]); XCTAssertEqual(cron.appName, "CRON"); XCTAssertEqual(cron.procID, "999")
        let noTag = parse(lines[3]); XCTAssertEqual(noTag.appName, "gateway", "ambiguous 'word:' after the timestamp is read as a tag"); XCTAssertEqual(noTag.message, "no tag at all")
        let noPri = parse(lines[4]); XCTAssertFalse(noPri.priorityPresent); XCTAssertEqual(noPri.hostname, "gateway"); XCTAssertEqual(noPri.appName, "app")
        let iso = parse(lines[5]); XCTAssertEqual(iso.eventTime?.date.timeIntervalSince1970, 1_789_061_723); XCTAssertFalse(iso.timeInferred)
    }

    func testYearInferenceAcrossNewYear() {
        let jan1 = Timestamp(Date(timeIntervalSince1970: 1_798_761_600))   // 2027-01-01 00:00:00 UTC
        let e = parser.parse(RawDatagram(receivedAt: jan1, kind: .syslog, transport: .udp, source: src, sourcePort: 1, localPort: 1,
                                         payload: Data("<14>Dec 31 23:59:50 gw app: late".utf8)))
        var utc = Calendar(identifier: .gregorian); utc.timeZone = TimeZone(identifier: "UTC")!
        print("year-inference: eventTime=\(String(describing: e.eventTime)) inferred=\(e.timeInferred) message=\(e.message) host=\(String(describing: e.hostname))")
        XCTAssertEqual(e.eventTime.map { utc.component(.year, from: $0.date) }, 2026, "December message received just after New Year belongs to the previous year")
        XCTAssertEqual(e.eventTime.map { $0.date.timeIntervalSince1970 }, 1_798_757_990, "Dec 31 23:59:50 Berlin = 22:59:50 UTC")
    }

    func testRFC5424HeaderAndStructuredData() throws {
        let lines = try fixture("rfc5424-generic")
        let e = parse(lines[0])
        XCTAssertEqual(e.syslogVersion, 1); XCTAssertEqual(e.facility, .local0); XCTAssertEqual(e.severity, .informational)
        XCTAssertEqual(e.hostname, "gateway"); XCTAssertEqual(e.appName, "netsentry-gen"); XCTAssertEqual(e.procID, "4242"); XCTAssertEqual(e.msgID, "ID7")
        XCTAssertEqual(e.eventTime?.date.timeIntervalSince1970 ?? 0, 1_789_061_723.123, accuracy: 0.001); XCTAssertFalse(e.timeInferred)
        XCTAssertEqual(e.structuredData["gen@32473"]?["seq"], "7")
        XCTAssertEqual(e.structuredData["gen@32473"]?["note"], "a \"quoted\" value ] with bracket")
        XCTAssertEqual(e.message, "sample structured message 7")
        let plain = parse(lines[1]); XCTAssertTrue(plain.structuredData.isEmpty); XCTAssertEqual(plain.message, "plain message without structured data"); XCTAssertNil(plain.procID)
        let dashes = parse(lines[2]); XCTAssertNil(dashes.eventTime); XCTAssertNil(dashes.hostname); XCTAssertEqual(dashes.message, "only dashes")
        let multi = parse(lines[3]); XCTAssertEqual(multi.structuredData.count, 2); XCTAssertEqual(multi.structuredData["b"]?["z"], "3"); XCTAssertEqual(multi.message, "")
    }

    func testNetfilterFirewallLines() throws {
        let lines = try fixture("unifi-firewall-netfilter")
        let deny = parse(lines[0])
        XCTAssertEqual(deny.eventType, .firewall); XCTAssertEqual(deny.parserName, "netfilter-log"); XCTAssertEqual(deny.parseStatus, .parsed)
        XCTAssertEqual(deny.action, .deny); XCTAssertEqual(deny.ruleName, "WAN_LOCAL-D-4001"); XCTAssertEqual(deny.ruleID, "4001")
        XCTAssertEqual(deny.srcIP?.description, "203.0.113.7"); XCTAssertEqual(deny.dstIP?.description, "192.168.99.1")
        XCTAssertEqual(deny.srcPort, 44321); XCTAssertEqual(deny.dstPort, 22); XCTAssertEqual(deny.protocolNumber, 6)
        XCTAssertEqual(deny.inInterface, "eth4"); XCTAssertNil(deny.outInterface); XCTAssertEqual(deny.deviceID, "00:11:22:33:44:55")
        XCTAssertEqual(deny.attributes["fw.flags"], "DF SYN"); XCTAssertEqual(deny.attributes["fw.ttl"], "53")
        XCTAssertEqual(deny.hostname, "UCG-Fiber"); XCTAssertEqual(deny.facility, .kern); XCTAssertEqual(deny.severity, .warning)
        let allow = parse(lines[1]); XCTAssertEqual(allow.action, .allow); XCTAssertEqual(allow.outInterface, "eth4"); XCTAssertEqual(allow.dstPort, 443)
        let reject = parse(lines[2]); XCTAssertEqual(reject.action, .reject); XCTAssertEqual(reject.protocolNumber, 1); XCTAssertEqual(reject.attributes["fw.type"], "8")
        let v6 = parse(lines[3]); XCTAssertEqual(v6.srcIP?.description, "2001:db8::7"); XCTAssertEqual(v6.protocolNumber, 17); XCTAssertEqual(v6.action, .unknown); XCTAssertNil(v6.ruleName)
    }

    func testDHCPAndDNS() throws {
        let dhcp = try fixture("unifi-dhcp-dnsmasq").map { parse($0) }
        XCTAssertEqual(dhcp.map(\.eventType), [.dhcp, .dhcp, .dhcp, .dhcp])
        XCTAssertEqual(dhcp[0].deviceID, "02:11:22:33:44:55"); XCTAssertNil(dhcp[0].srcIP); XCTAssertEqual(dhcp[0].attributes["dhcp.message"], "DISCOVER")
        XCTAssertEqual(dhcp[3].srcIP?.description, "192.168.99.31"); XCTAssertEqual(dhcp[3].attributes["dhcp.hostname"], "nas-01"); XCTAssertEqual(dhcp[3].inInterface, "br0")
        let dns = try fixture("unifi-dns-dnsmasq").map { parse($0) }
        XCTAssertEqual(dns[0].eventType, .dns); XCTAssertEqual(dns[0].attributes["dns.name"], "example.com"); XCTAssertEqual(dns[0].attributes["dns.type"], "A"); XCTAssertEqual(dns[0].srcIP?.description, "192.168.99.31")
        XCTAssertEqual(dns[1].dstIP?.description, "1.1.1.1"); XCTAssertEqual(dns[2].dstIP?.description, "203.0.113.50")
    }

    func testOpenSSHAndSuricata() throws {
        let auth = try fixture("unifi-auth-openssh").map { parse($0) }
        XCTAssertEqual(auth[0].username, "admin"); XCTAssertEqual(auth[0].attributes["auth.result"], "success"); XCTAssertEqual(auth[0].attributes["auth.method"], "publickey"); XCTAssertEqual(auth[0].srcPort, 51234)
        XCTAssertEqual(auth[1].username, "root"); XCTAssertEqual(auth[1].attributes["auth.result"], "failure"); XCTAssertEqual(auth[1].srcIP?.description, "203.0.113.99")
        XCTAssertEqual(auth[2].username, "oracle"); XCTAssertEqual(auth[2].attributes["auth.result"], "failure")
        XCTAssertEqual(auth[3].eventType, .auth)
        let ids = try fixture("unifi-ids-suricata").map { parse($0) }
        XCTAssertEqual(ids[0].eventType, .ids); XCTAssertEqual(ids[0].idsSignatureID, 2001219); XCTAssertEqual(ids[0].idsSignature, "ET SCAN Potential SSH Scan")
        XCTAssertEqual(ids[0].idsCategory, "Attempted Information Leak"); XCTAssertEqual(ids[0].idsSeverity, 2); XCTAssertEqual(ids[0].action, .alert)
        XCTAssertEqual(ids[0].srcIP?.description, "203.0.113.99"); XCTAssertEqual(ids[0].srcPort, 41234); XCTAssertEqual(ids[0].dstPort, 22); XCTAssertEqual(ids[0].protocolNumber, 6)
        XCTAssertEqual(ids[1].action, .block); XCTAssertEqual(ids[1].idsSignatureID, 2100498)
        XCTAssertEqual(ids[2].protocolNumber, 1); XCTAssertEqual(ids[2].srcIP?.description, "203.0.113.5"); XCTAssertNil(ids[2].srcPort)
    }

    func testFallbackKeepsEverything() throws {
        for line in try fixture("unknown-fallback") {
            let e = parse(line)
            XCTAssertEqual(e.raw, line)
            XCTAssertNotEqual(e.eventType, .firewall)
            XCTAssertFalse(e.raw!.isEmpty)
        }
        let junk = parse("not syslog at all")
        XCTAssertEqual(junk.parseStatus, .unparsed); XCTAssertEqual(junk.parserName, "fallback"); XCTAssertFalse(junk.priorityPresent)
        let badPri = parse("<999>bad priority stays part of the message")
        XCTAssertFalse(badPri.priorityPresent); XCTAssertTrue(badPri.message.hasPrefix("<999>"))
    }

    func testBinaryAndOversizedInputAreBoundedAndFlagged() {
        let binary = Data([0xff, 0xfe, 0x00, 0x41, 0x42])
        let e = parser.parse(RawDatagram(receivedAt: received, kind: .syslog, transport: .udp, source: src, sourcePort: 1, localPort: 1, payload: binary))
        XCTAssertEqual(e.attributes["raw.lossyUTF8"], "true"); XCTAssertNotNil(e.rawBytes)
        let huge = Data(repeating: 0x41, count: 100_000)
        let h = parser.parse(RawDatagram(receivedAt: received, kind: .syslog, transport: .udp, source: src, sourcePort: 1, localPort: 1, payload: huge))
        XCTAssertEqual(h.attributes["raw.truncated"], "true"); XCTAssertEqual(h.message.count, SyslogParser.maxMessageBytes)
    }

    func testFuzzNeverCrashes() throws {
        var rng = SystemRandomNumberGenerator()
        let seeds = try ["rfc3164-generic", "rfc5424-generic", "unifi-firewall-netfilter", "unifi-ids-suricata"].flatMap(fixture)
        for _ in 0..<2_000 {
            var bytes = Data(seeds[Int.random(in: 0..<seeds.count, using: &rng)].utf8)
            for _ in 0..<Int.random(in: 1...4, using: &rng) {
                switch Int.random(in: 0..<3, using: &rng) {
                case 0: if !bytes.isEmpty { bytes[Int.random(in: 0..<bytes.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng) }
                case 1: bytes = bytes.prefix(Int.random(in: 0...bytes.count, using: &rng))
                default: bytes.insert(UInt8.random(in: 0...255, using: &rng), at: Int.random(in: 0...bytes.count, using: &rng))
                }
            }
            _ = parser.parse(RawDatagram(receivedAt: received, kind: .syslog, transport: .udp, source: src, sourcePort: 1, localPort: 1, payload: bytes))
        }
    }

    func testTCPFramingOctetCountingAndNonTransparent() {
        var f = SyslogTCPFramer()
        let m1 = "<14>1 - h a - - - one", m2 = "<14>1 - h a - - - two"
        let stream = Data("\(m1.utf8.count) \(m1)\(m2.utf8.count) \(m2)<14>three\r\n<14>four\n<14>partial".utf8)
        var out: [String] = []
        for chunk in stride(from: 0, to: stream.count, by: 7) {
            out += f.append(stream[chunk..<min(chunk + 7, stream.count)]).map { String(decoding: $0, as: UTF8.self) }
        }
        XCTAssertEqual(out, [m1, m2, "<14>three", "<14>four"])
        XCTAssertEqual(f.flush().map { String(decoding: $0, as: UTF8.self) }, "<14>partial")
    }

    func testRegistryDescribesEveryParserWithVersions() {
        let d = ParserRegistry.descriptors
        XCTAssertTrue(d.contains { $0.name == "netfilter-log" && $0.version == 1 && !$0.verified })
        XCTAssertTrue(d.contains { $0.name == "syslog-header" && $0.verified })
        XCTAssertFalse(ParserRegistry.combinedVersion.isEmpty)
    }
}
