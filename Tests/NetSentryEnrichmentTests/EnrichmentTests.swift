import XCTest
@testable import NetSentryEnrichment
import NetSentryCore
import NetSentryPersistence
import NetSentryDevTools

final class MMDBReaderTests: XCTestCase {
    func testLookupsAcrossPrefixesAndTypes() throws {
        var w = MMDBWriter()
        w.databaseType = "GeoLite2-Country-Test"
        let data = w.build([
            .init(prefix: IPPrefix("203.0.113.0/24")!, record: ["country": ["iso_code": "DE", "names": ["en": "Germany"]], "autonomous_system_number": UInt32(3320), "autonomous_system_organization": "Deutsche Telekom"]),
            .init(prefix: IPPrefix("198.51.100.0/24")!, record: ["country": ["iso_code": "US"], "autonomous_system_number": UInt32(13335), "autonomous_system_organization": "Cloudflare", "score": 0.75, "flag": true, "big": UInt64(1) << 40]),
            .init(prefix: IPPrefix("2001:db8::/32")!, record: ["country": ["iso_code": "NL"], "autonomous_system_number": UInt32(1103)]),
        ])
        let r = try MMDBReader(data: data)
        XCTAssertEqual(r.metadata.recordSize, 24); XCTAssertEqual(r.metadata.ipVersion, 6); XCTAssertEqual(r.metadata.databaseType, "GeoLite2-Country-Test")
        XCTAssertEqual(r.geo(IPAddress("203.0.113.77")!).countryISO, "DE")
        XCTAssertEqual(r.geo(IPAddress("203.0.113.77")!).asn, 3320)
        XCTAssertEqual(r.geo(IPAddress("203.0.113.77")!).organization, "Deutsche Telekom")
        XCTAssertEqual(r.geo(IPAddress("198.51.100.1")!).countryISO, "US")
        XCTAssertEqual(r.lookup(IPAddress("198.51.100.1")!)?["score"], .double(0.75))
        XCTAssertEqual(r.lookup(IPAddress("198.51.100.1")!)?["flag"], .bool(true))
        XCTAssertEqual(r.lookup(IPAddress("198.51.100.1")!)?["big"]?.uintValue, 1 << 40)
        XCTAssertEqual(r.lookup(IPAddress("203.0.113.1")!)?["country"]?["names"]?["en"]?.stringValue, "Germany")
        XCTAssertEqual(r.geo(IPAddress("2001:db8:1234::1")!).countryISO, "NL")
        XCTAssertNil(r.lookup(IPAddress("8.8.8.8")!), "unknown address is nil, not an error")
        XCTAssertNil(r.lookup(IPAddress("2001:db9::1")!))
        XCTAssertEqual(r.geo(IPAddress("10.0.0.1")!), MMDBReader.GeoResult())
    }

    func testCorruptAndTruncatedInputsDoNotCrash() {
        XCTAssertThrowsError(try MMDBReader(data: Data(count: 100)))
        var w = MMDBWriter()
        let good = w.build([.init(prefix: IPPrefix("203.0.113.0/24")!, record: ["country": ["iso_code": "DE"]])])
        for cut in stride(from: 1, to: good.count, by: 7) {
            _ = try? MMDBReader(data: good.prefix(cut))
        }
        var mutated = good
        for i in stride(from: 0, to: mutated.count, by: 3) { mutated[i] ^= 0x5A }
        if let r = try? MMDBReader(data: mutated) { _ = r.lookup(IPAddress("203.0.113.1")!) }
        w.databaseType = "x"
        XCTAssertNotNil(try? MMDBReader(data: good))
    }
}

final class EntityResolverTests: XCTestCase {
    private func tempRoot() -> URL {
        let u = FileManager.default.temporaryDirectory.appending(path: "netsentry-entities-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: u) }
        return u
    }

    func testIdentityLifecycleMergeSplitAndHistory() async throws {
        let meta = try MetaStore(root: tempRoot())
        let r = try await EntityResolver(meta: meta, internalPrefixes: [IPPrefix("192.168.99.0/24")!])
        let t1 = Timestamp(seconds: 1_789_000_000), t2 = t1 + .seconds(3_600), t3 = t2 + .seconds(3_600)
        let ip = IPAddress("192.168.99.31")!
        // Flow-inferred client without MAC, then DHCP lease adds MAC + hostname to the same identity.
        let a = try await r.observe(ip: ip, at: t1, source: "ipfix")
        XCTAssertNotNil(a)
        let b = try await r.observe(ip: ip, mac: "AA:BB:CC:00:11:22", hostname: "nas-01", at: t2, source: "dhcp")
        XCTAssertEqual(a, b)
        let c1 = try await r.client(id: a!)
        XCTAssertEqual(c1?.hostname, "nas-01"); XCTAssertEqual(c1?.primaryMAC, "aa:bb:cc:00:11:22"); XCTAssertEqual(c1?.addresses, ["192.168.99.31"])
        // The DHCP server hands the address to a different MAC: a new client, and the history keeps the old owner.
        let other = try await r.observe(ip: ip, mac: "AA:BB:CC:99:99:99", hostname: "laptop", at: t3, source: "dhcp")
        XCTAssertNotEqual(other, a)
        let ownerThen = try await r.clientID(for: ip, at: t2 + .seconds(60))
        XCTAssertEqual(ownerThen, a, "historical lookup returns the client that held the address at that time")
        let ownerNow = try await r.clientID(for: ip, at: t3 + .seconds(60))
        XCTAssertEqual(ownerNow, other)
        let current1 = await r.clientID(for: ip)
        XCTAssertEqual(current1, other)
        let external = try await r.observe(ip: IPAddress("8.8.8.8")!, at: t1, source: "ipfix")
        XCTAssertNil(external, "external addresses never become clients")
        // Rename, tags, notes, trusted.
        try await r.rename(a!, to: "NAS"); try await r.setTags(a!, ["storage", "trusted-device"]); try await r.setNotes(a!, "Synology in the closet"); try await r.setTrusted(a!, true)
        let c2 = try await r.client(id: a!)
        XCTAssertEqual(c2?.displayName, "NAS"); XCTAssertEqual(Set(c2?.tags ?? []), ["storage", "trusted-device"]); XCTAssertEqual(c2?.notes, "Synology in the closet"); XCTAssertEqual(c2?.trusted, true); XCTAssertEqual(c2?.label, "NAS")
        // Merge the laptop identity into the NAS (user says they are the same device), then split it back out.
        try await r.merge(other!, into: a!)
        let afterMerge = await r.clientID(for: ip)
        XCTAssertEqual(afterMerge, a)
        let all = try await r.allClients()
        XCTAssertEqual(all.count, 1)
        let split = try await r.split(ip: ip, from: a!, at: t3 + .seconds(7_200))
        XCTAssertNotEqual(split, a)
        let afterSplit = await r.clientID(for: ip)
        XCTAssertEqual(afterSplit, split)
        let changes = await r.drainChanges()
        XCTAssertTrue(changes.contains { $0.kind == .created }); XCTAssertTrue(changes.contains { $0.kind == .addressMoved }); XCTAssertTrue(changes.contains { $0.kind == .hostnameLearned })
        try await r.flushLastSeen()
        let flushed = try await r.client(id: a!)
        XCTAssertEqual(flushed?.lastSeen, t2 + .seconds(0), "last seen tracks the newest observation of that client")
    }

    func testEnricherAppliesIdentityGeoAndServiceNames() async throws {
        let meta = try MetaStore(root: tempRoot())
        let resolver = try await EntityResolver(meta: meta, internalPrefixes: [])
        var w = MMDBWriter()
        let db = w.build([.init(prefix: IPPrefix("203.0.113.0/24")!, record: ["country": ["iso_code": "DE"], "autonomous_system_number": UInt32(3320), "autonomous_system_organization": "Telekom"])])
        let path = FileManager.default.temporaryDirectory.appending(path: "geo-\(UUID().uuidString).mmdb"); try db.write(to: path)
        let e = Enricher(resolver: resolver, geoDatabasePath: path.path)
        let t = Timestamp(seconds: 1_789_000_000)
        var f = FlowRecord(exporter: ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0), exportSequence: 1, receivedAt: t, exportTime: t, startTime: t, endTime: t,
                           srcIP: IPAddress("192.168.99.31")!, dstIP: IPAddress("203.0.113.9")!)
        f.dstPort = 443; f.protocolNumber = 6; f.enrichment.srcInternal = true; f.enrichment.direction = .outbound
        f.extraElements = [RawInformationElement(enterpriseNumber: 0, elementID: 56, value: Data([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))]
        await e.enrich(&f)
        XCTAssertNotNil(f.enrichment.srcClientID); XCTAssertNil(f.enrichment.dstClientID)
        XCTAssertEqual(f.enrichment.dstCountry, "DE"); XCTAssertEqual(f.enrichment.dstASN, 3320); XCTAssertEqual(f.enrichment.dstOrganization, "Telekom")
        XCTAssertEqual(f.enrichment.service, "https"); XCTAssertEqual(f.enrichment.enrichmentVersion, Enricher.version)
        let client = try await resolver.client(id: f.enrichment.srcClientID!)
        XCTAssertEqual(client?.primaryMAC, "00:11:22:33:44:55", "IPFIX source MAC is attached to the client")
        var ev = SyslogEvent(receivedAt: t, sourceIP: IPAddress("192.168.99.1")!, transport: .udp, message: "DHCPACK(br0) 192.168.99.31 00:11:22:33:44:55 nas-01", raw: nil)
        ev.eventType = .dhcp; ev.srcIP = IPAddress("192.168.99.31"); ev.deviceID = "00:11:22:33:44:55"; ev.attributes = ["dhcp.message": "ACK", "dhcp.hostname": "nas-01"]; ev.enrichment.srcInternal = true
        await e.enrich(&ev)
        XCTAssertEqual(ev.enrichment.srcClientID, f.enrichment.srcClientID, "the DHCP lease resolves to the same client via the MAC")
        let leased = try await resolver.client(id: ev.enrichment.srcClientID!)
        XCTAssertEqual(leased?.hostname, "nas-01")
        XCTAssertEqual(ServiceNames.name(port: 53, protocolNumber: 17), "dns"); XCTAssertEqual(ServiceNames.name(port: 853, protocolNumber: 6), "dns-over-tls"); XCTAssertNil(ServiceNames.name(port: 60000, protocolNumber: 6))
    }
}
