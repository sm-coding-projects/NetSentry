import XCTest
@testable import NetSentryEnrichment
import NetSentryCore
import NetSentryPersistence

final class EntityResolverHysteresisTests: XCTestCase {

    /// A single record carrying a different MAC must not reassign an address; repeated observations must.
    func testAddressMoveRequiresRepeatedObservations() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "netsentry-resolver-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let meta = try MetaStore(root: root)
        let resolver = try await EntityResolver(meta: meta, internalPrefixes: [])
        let ip = IPAddress("192.168.1.50")!
        let t0 = NetSentryCore.Timestamp(seconds: 1_790_000_000)
        let a = try await resolver.observe(ip: ip, mac: "aa:aa:aa:aa:aa:01", at: t0, source: "ipfix")!
        // One stray record with another MAC: still client a.
        let stray = try await resolver.observe(ip: ip, mac: "bb:bb:bb:bb:bb:02", at: t0 + .seconds(1), source: "ipfix")
        XCTAssertEqual(stray, a)
        // The original device answers again: the pending move is discarded.
        let back = try await resolver.observe(ip: ip, mac: "aa:aa:aa:aa:aa:01", at: t0 + .seconds(2), source: "ipfix"); XCTAssertEqual(back, a)
        let n1 = try await resolver.observe(ip: ip, mac: "bb:bb:bb:bb:bb:02", at: t0 + .seconds(3), source: "ipfix"); XCTAssertEqual(n1, a)
        let n2 = try await resolver.observe(ip: ip, mac: "bb:bb:bb:bb:bb:02", at: t0 + .seconds(4), source: "ipfix"); XCTAssertEqual(n2, a)
        // Third consecutive observation of the new MAC: the address moves to a new client, history closed at the first sighting.
        let b = try await resolver.observe(ip: ip, mac: "bb:bb:bb:bb:bb:02", at: t0 + .seconds(5), source: "ipfix")!
        XCTAssertNotEqual(a, b)
        let ownerEarly = try await resolver.clientID(for: ip, at: t0 + .seconds(2)); XCTAssertEqual(ownerEarly, a)
        let ownerLate = try await resolver.clientID(for: ip, at: t0 + .seconds(10)); XCTAssertEqual(ownerLate, b)
        let clients = try await resolver.allClients()
        XCTAssertEqual(clients.count, 2)
        XCTAssertEqual(clients.first { $0.id == b }?.addresses, ["192.168.1.50"])
        XCTAssertEqual(clients.first { $0.id == a }?.addresses, [])
    }
}
