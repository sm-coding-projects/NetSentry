import XCTest
@testable import NetSentryCore

final class IPAddressTests: XCTestCase {
    func testIPv4RoundTrip() {
        let a = IPAddress("192.168.1.10")!
        XCTAssertEqual(a.version, 4)
        XCTAssertEqual(a.description, "192.168.1.10")
        XCTAssertEqual(a.v4Value, 0xC0A8010A)
        XCTAssertEqual(a.bytes, [192, 168, 1, 10])
        XCTAssertEqual(IPAddress(bytes: [192, 168, 1, 10]), a)
        XCTAssertTrue(a.isPrivate)
        XCTAssertFalse(a.isLoopback)
    }

    func testIPv6RoundTripAndCanonicalForm() {
        let a = IPAddress("2001:DB8:0:0:0:0:0:1")!
        XCTAssertEqual(a.version, 6)
        XCTAssertEqual(a.description, "2001:db8::1")
        XCTAssertEqual(a.bytes.count, 16)
        XCTAssertEqual(IPAddress(bytes: a.bytes), a)
        XCTAssertFalse(a.isPrivate)
        XCTAssertTrue(IPAddress("fd12::1")!.isPrivate)
        XCTAssertTrue(IPAddress("fe80::1")!.isLinkLocal)
        XCTAssertTrue(IPAddress("::1")!.isLoopback)
        XCTAssertTrue(IPAddress("ff02::1")!.isMulticast)
    }

    func testInvalidInputs() {
        XCTAssertNil(IPAddress("not an ip"))
        XCTAssertNil(IPAddress("300.1.1.1"))
        XCTAssertNil(IPAddress(bytes: [1, 2, 3]))
        XCTAssertNil(IPPrefix("10.0.0.0/33"))
        XCTAssertNil(IPPrefix("10.0.0.0/abc"))
    }

    func testPrefixContainment() {
        let p = IPPrefix("10.0.0.0/8")!
        XCTAssertTrue(p.contains(IPAddress("10.255.1.1")!))
        XCTAssertFalse(p.contains(IPAddress("11.0.0.1")!))
        XCTAssertEqual(IPAddress("::ffff:10.0.0.1"), IPAddress("10.0.0.1"))   // v4-mapped normalizes to v4
        XCTAssertTrue(p.contains(IPAddress("::ffff:10.0.0.1")!))
        let p6 = IPPrefix("fd00::/8")!
        XCTAssertTrue(p6.contains(IPAddress("fdab:1::5")!))
        XCTAssertFalse(p6.contains(IPAddress("fe80::1")!))
        XCTAssertFalse(p6.contains(IPAddress("10.0.0.1")!))
        let host = IPPrefix("192.168.7.3")!
        XCTAssertEqual(host.prefixLength, 32)
        XCTAssertTrue(host.contains(IPAddress("192.168.7.3")!))
        XCTAssertFalse(host.contains(IPAddress("192.168.7.4")!))
        XCTAssertTrue(IPPrefix("0.0.0.0/0")!.contains(IPAddress("8.8.8.8")!))
        let p64 = IPPrefix("2001:db8:1:2::/64")!
        XCTAssertTrue(p64.contains(IPAddress("2001:db8:1:2:ffff::1")!))
        XCTAssertFalse(p64.contains(IPAddress("2001:db8:1:3::1")!))
        let p100 = IPPrefix("2001:db8::/100")!
        XCTAssertTrue(p100.contains(IPAddress("2001:db8::0fff:ffff")!))
        XCTAssertFalse(p100.contains(IPAddress("2001:db8::1000:0")!))
    }

    func testMACAddress() {
        XCTAssertEqual(MACAddress("AA:bb:CC:00:11:22")?.description, "aa:bb:cc:00:11:22")
        XCTAssertEqual(MACAddress("aa-bb-cc-00-11-22")?.value, 0xAABBCC001122)
        XCTAssertNil(MACAddress("zz:bb:cc:00:11:22"))
    }

    func testTimestampBuckets() {
        let t = Timestamp(microseconds: 1_700_000_123_456_789)
        XCTAssertEqual(t.truncated(to: 60_000_000).microseconds % 60_000_000, 0)
        XCTAssertLessThanOrEqual(t.truncated(to: 60_000_000), t)
        XCTAssertEqual((t + .seconds(1)).microseconds - t.microseconds, 1_000_000)
    }
}
