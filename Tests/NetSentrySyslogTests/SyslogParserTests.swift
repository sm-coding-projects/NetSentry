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
        // Real UCG Fiber zone-policy shape: repeated hostname, no kernel tag, DESCR="…" rule name, trailing space.
        let zone = parse(lines[4])
        XCTAssertEqual(zone.parserName, "netfilter-log"); XCTAssertEqual(zone.parseStatus, .parsed); XCTAssertNil(zone.appName); XCTAssertEqual(zone.hostname, "UCG-Fiber")
        XCTAssertEqual(zone.ruleName, "Internal_to_MediaServer"); XCTAssertEqual(zone.attributes["fw.label"], "LAN_DMZ-A-10000"); XCTAssertEqual(zone.ruleID, "10000"); XCTAssertEqual(zone.action, .allow)
        XCTAssertEqual(zone.srcIP?.description, "192.168.99.31"); XCTAssertEqual(zone.dstIP?.description, "192.168.30.80"); XCTAssertEqual(zone.dstPort, 8989); XCTAssertEqual(zone.outInterface, "br30")
        XCTAssertEqual(zone.attributes["fw.mark"], "1a0000"); XCTAssertEqual(zone.attributes["fw.flags"], "DF SYN"); XCTAssertEqual(zone.deviceID, "02:d5:18:8c:f7:71")
        let zone2 = parse(lines[5]); XCTAssertEqual(zone2.ruleName, "HA_to_Solar"); XCTAssertEqual(zone2.dstPort, 502); XCTAssertEqual(zone2.attributes["fw.flags"], "DF ACK PSH")
    }

    func testDHCPAndDNS() throws {
        let dhcp = try fixture("unifi-dhcp-dnsmasq").map { parse($0) }
        XCTAssertEqual(dhcp.map(\.eventType), [.dhcp, .dhcp, .dhcp, .dhcp, .dhcp])
        XCTAssertEqual(dhcp[4].parserName, "dnsmasq-dhcp"); XCTAssertEqual(dhcp[4].appName, "dnsmasq-dhcp"); XCTAssertEqual(dhcp[4].procID, "1097397"); XCTAssertEqual(dhcp[4].srcIP?.description, "192.168.99.128"); XCTAssertEqual(dhcp[4].deviceID, "02:bf:a0:81:ff:f6")
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

    func testUniFiDeviceWrappersAndTags() throws {
        let e = try fixture("unifi-device-tag").map { parse($0) }
        XCTAssertEqual(e.count, 20)
        for x in e { XCTAssertEqual(x.attributes["unifi.device"], "true", x.raw ?? "") }

        // AP "<mac>,<model>-<fw>:" wrapper with a path tag.
        XCTAssertEqual(e[0].hostname, "AP-Kitchen"); XCTAssertEqual(e[0].appName, "hostapd"); XCTAssertEqual(e[0].procID, "4628")
        XCTAssertEqual(e[0].deviceID, "02:ea:14:e3:1d:e9"); XCTAssertEqual(e[0].attributes["unifi.model"], "U6-Pro"); XCTAssertEqual(e[0].attributes["unifi.firmware"], "6.8.2+15592")
        XCTAssertTrue(e[0].message.hasPrefix("ap_handle_timer: register"), e[0].message)
        XCTAssertEqual(e[0].eventType, .client); XCTAssertEqual(e[0].parserName, "process-table"); XCTAssertEqual(e[0].parseStatus, .partial)
        XCTAssertEqual(e[0].attributes["class.by"], "process:hostapd")
        // Empty tag, doubled tag, kernel wlan / DHCP-SM prefixes.
        XCTAssertEqual(e[1].appName, "wevent"); XCTAssertEqual(e[1].procID, "4278"); XCTAssertEqual(e[1].eventType, .client); XCTAssertTrue(e[1].message.hasPrefix("wevent.ubnt_custom_event"))
        XCTAssertEqual(e[2].appName, "stahtd"); XCTAssertEqual(e[2].procID, "28816"); XCTAssertEqual(e[2].eventType, .client)
        XCTAssertEqual(e[3].appName, "kernel"); XCTAssertNil(e[3].procID); XCTAssertEqual(e[3].eventType, .client); XCTAssertEqual(e[3].attributes["class.by"], "kernel:wlan")
        XCTAssertEqual(e[4].eventType, .dhcp)
        XCTAssertEqual(e[5].appName, "udhcpc"); XCTAssertEqual(e[5].procID, "32136"); XCTAssertEqual(e[5].eventType, .dhcp); XCTAssertTrue(e[5].message.hasPrefix("udhcpc: lease of"))
        // Switch: "switch:" tag is kept (the inner word has no pid), DHCP snooping by message prefix.
        XCTAssertEqual(e[6].appName, "switch"); XCTAssertEqual(e[6].eventType, .unifiOther); XCTAssertEqual(e[6].attributes["unifi.model"], "US-8-60W"); XCTAssertEqual(e[6].attributes["unifi.firmware"], "7.5.15+17146")
        XCTAssertEqual(e[7].eventType, .dhcp)
        XCTAssertEqual(e[8].appName, "swctrl"); XCTAssertEqual(e[8].procID, "4064"); XCTAssertEqual(e[8].eventType, .unifiOther)
        // No timestamp at all.
        XCTAssertNil(e[9].eventTime); XCTAssertEqual(e[9].hostname, "SW-Flex"); XCTAssertEqual(e[9].appName, "INF-DB"); XCTAssertEqual(e[9].attributes["unifi.model"], "USW_FLEX_MINI"); XCTAssertEqual(e[9].attributes["unifi.firmware"], "2.1.6.762"); XCTAssertEqual(e[9].eventType, .unifiOther)
        // Gateway lines repeat the hostname.
        XCTAssertEqual(e[10].hostname, "UCG-Fiber"); XCTAssertEqual(e[10].appName, "dpi-flow-stats"); XCTAssertEqual(e[10].procID, "2847"); XCTAssertTrue(e[10].message.hasPrefix("ubnt-dpi-util: connect")); XCTAssertEqual(e[10].eventType, .unifiOther)
        XCTAssertEqual(e[11].appName, "sudo"); XCTAssertEqual(e[11].eventType, .auth)
        XCTAssertEqual(e[12].appName, "teleportd"); XCTAssertEqual(e[12].procID, "3875"); XCTAssertEqual(e[12].eventType, .vpn)
        XCTAssertEqual(e[13].parserName, "dnsmasq-dhcp"); XCTAssertEqual(e[13].parseStatus, .parsed); XCTAssertEqual(e[13].srcIP?.description, "192.168.99.128"); XCTAssertEqual(e[13].deviceID, "02:bf:a0:81:ff:f6")
        XCTAssertEqual(e[14].appName, "CRON"); XCTAssertEqual(e[14].eventType, .auth)
        XCTAssertEqual(e[15].eventType, .system); XCTAssertEqual(e[15].attributes["class.by"], "process:kernel")
        XCTAssertEqual(e[16].eventType, .ids)
        XCTAssertEqual(e[17].eventType, .system); XCTAssertEqual(e[17].attributes["class.by"], "process-prefix:systemd")
        // Netfilter behind the repeated hostname: the rule label must come out clean.
        XCTAssertEqual(e[18].parserName, "netfilter-log"); XCTAssertEqual(e[18].ruleName, "WAN_LOCAL-D-4001"); XCTAssertEqual(e[18].action, .deny); XCTAssertEqual(e[18].appName, "kernel")
        // Unlisted daemon on a recognized UniFi device defaults to System.
        XCTAssertEqual(e[19].appName, "some-new-daemon"); XCTAssertEqual(e[19].eventType, .system); XCTAssertEqual(e[19].attributes["class.by"], "unifi-device-default")

        // Non-UniFi lines are left alone: unknown app names stay Unknown, plain tags are untouched.
        let plain = parse("<14>Sep 10 19:35:23 gateway myapp[7]: hello")
        XCTAssertNil(plain.attributes["unifi.device"]); XCTAssertEqual(plain.appName, "myapp"); XCTAssertEqual(plain.eventType, .unknown); XCTAssertEqual(plain.parserName, "syslog-header")
        let known = parse("<14>Sep 10 19:35:23 gateway teleportd[7]: hello")
        XCTAssertEqual(known.eventType, .vpn, "table entries apply everywhere; only the System default is UniFi-only")
    }

    func testCEFEvents() throws {
        let e = try fixture("unifi-cef").map { parse($0) }
        XCTAssertEqual(e.count, 11)
        for x in e.dropLast() {
            XCTAssertEqual(x.parserName, "cef"); XCTAssertEqual(x.parseStatus, .parsed); XCTAssertFalse(x.priorityPresent); XCTAssertNotNil(x.eventTime)
            XCTAssertEqual(x.hostname, "UCG-Fiber"); XCTAssertEqual(x.appName, "UniFi Network"); XCTAssertEqual(x.attributes["cef.vendor"], "Ubiquiti")
        }
        let threat = e[0]
        XCTAssertEqual(threat.eventType, .ids); XCTAssertEqual(threat.ruleID, "200"); XCTAssertEqual(threat.ruleName, "Threat Detected")
        XCTAssertEqual(threat.idsSignature, "ET CINS Active Threat Intelligence Poor Reputation IP group 249"); XCTAssertEqual(threat.idsSignatureID, 2403548)
        XCTAssertEqual(threat.idsCategory, "CINS Army Reputation List"); XCTAssertEqual(threat.idsSeverity, 2, "medium risk → Suricata-style priority 2")
        XCTAssertEqual(threat.srcPort, 47117); XCTAssertEqual(threat.dstPort, 43284); XCTAssertEqual(threat.protocolNumber, 17); XCTAssertEqual(threat.action, .allow)
        XCTAssertEqual(threat.deviceID, "02:0c:29:e7:8b:ac"); XCTAssertNil(threat.srcIP)
        XCTAssertEqual(threat.attributes["cef.deviceOutboundInterface"], "Internet 1", "values keep their spaces")
        XCTAssertEqual(threat.attributes["cef.UNIFIflowStartTime"], "Sep 20, 2026 at 12:55:26.895 PM")
        XCTAssertEqual(threat.attributes["cef.severity"], "7"); XCTAssertEqual(threat.attributes["cef.product_version"], "10.6.106")
        XCTAssertTrue(threat.message.hasPrefix("A network intrusion attempt"), "msg= becomes the readable message; raw keeps the CEF line")
        XCTAssertTrue(threat.raw!.contains("CEF:0|Ubiquiti"))
        XCTAssertEqual(e[1].idsSeverity, 1); XCTAssertEqual(e[1].idsCategory, "P2P"); XCTAssertEqual(e[1].idsSignatureID, 2008581)
        let connected = e[2]
        XCTAssertEqual(connected.eventType, .client); XCTAssertEqual(connected.deviceID, "02:4a:39:d2:38:67"); XCTAssertEqual(connected.srcIP?.description, "192.168.20.95")
        XCTAssertEqual(connected.ruleName, "WiFi Client Connected"); XCTAssertEqual(connected.attributes["cef.UNIFIwifiName"], "Home-IoT"); XCTAssertNil(connected.action)
        XCTAssertEqual(e[3].eventType, .client); XCTAssertEqual(e[4].eventType, .client); XCTAssertEqual(e[5].eventType, .client); XCTAssertEqual(e[5].deviceID, "02:24:11:14:61:fe")
        XCTAssertEqual(e[6].eventType, .auth); XCTAssertEqual(e[6].username, "admin"); XCTAssertEqual(e[6].srcIP?.description, "192.168.99.100")
        XCTAssertEqual(e[7].eventType, .vpn); XCTAssertEqual(e[7].username, "UTR 02:41:b2:aa:76:57"); XCTAssertEqual(e[7].srcIP?.description, "192.168.2.5")
        XCTAssertEqual(e[8].eventType, .system); XCTAssertEqual(e[8].deviceID, "02:0b:8b:1a:c9:10"); XCTAssertEqual(e[8].ruleID, "112")
        XCTAssertEqual(e[9].eventType, .system); XCTAssertEqual(e[9].attributes["cef.UNIFIreportedDuration"], "22s")
        // Generic (non-UniFi) CEF inside an RFC 5424 message, with escapes.
        let generic = e[10]
        XCTAssertEqual(generic.parserName, "cef"); XCTAssertEqual(generic.eventType, .system); XCTAssertEqual(generic.appName, "vendorapp")
        XCTAssertEqual(generic.srcIP?.description, "203.0.113.9"); XCTAssertEqual(generic.dstIP?.description, "192.168.99.10"); XCTAssertEqual(generic.dstPort, 22); XCTAssertEqual(generic.protocolNumber, 6)
        XCTAssertEqual(generic.action, .block); XCTAssertEqual(generic.message, "A=B \\ slash"); XCTAssertEqual(generic.ruleName, "Blocked connection")
    }

    func testCEFHeaderEscapesAndRejects() {
        let esc = parse("<14>Sep 10 19:35:23 h CEF:0|Ac\\|me|Fire\\\\wall|1|7|Pipe \\| name|3|src=10.0.0.1")
        XCTAssertEqual(esc.parserName, "cef"); XCTAssertEqual(esc.attributes["cef.vendor"], "Ac|me"); XCTAssertEqual(esc.attributes["cef.product"], "Fire\\wall"); XCTAssertEqual(esc.ruleName, "Pipe | name")
        XCTAssertNotEqual(parse("<14>Sep 10 19:35:23 h CEF:0|only|three").parserName, "cef")
        XCTAssertNotEqual(parse("<14>Sep 10 19:35:23 h CEF: not a header").parserName, "cef")
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
        XCTAssertTrue(d.contains { $0.name == "netfilter-log" && $0.version == 2 && $0.verified })
        XCTAssertTrue(d.contains { $0.name == "dnsmasq-dhcp" && $0.verified })
        XCTAssertTrue(d.contains { $0.name == "openssh-auth" && !$0.verified })
        XCTAssertTrue(d.contains { $0.name == "syslog-header" && $0.verified })
        XCTAssertTrue(d.contains { $0.name == "unifi-device-tag" && $0.verified })
        XCTAssertTrue(d.contains { $0.name == "cef" && $0.verified && $0.family == .unknown })
        XCTAssertTrue(d.contains { $0.name == "process-table" && $0.verified })
        XCTAssertTrue(ParserRegistry.defaultParsers.last is ProcessTableParser, "the process table must classify last")
        XCTAssertFalse(ParserRegistry.combinedVersion.isEmpty)
    }
}
