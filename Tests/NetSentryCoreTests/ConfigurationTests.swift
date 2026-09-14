import XCTest
@testable import NetSentryCore

final class ConfigurationTests: XCTestCase {
    func testDefaultsAreValid() {
        let c = CollectorConfiguration(storageRoot: "/tmp/x")
        XCTAssertEqual(c.validate(), [])
        XCTAssertEqual(c.listeners.count, 4)
        XCTAssertTrue(c.allocation.isValid)
    }

    func testValidationCatchesBadValues() {
        var c = CollectorConfiguration(storageRoot: "")
        c.budgetBytes = 1
        c.listeners = [.init(kind: .ipfix, transport: .udp, port: 514), .init(kind: .syslog, transport: .udp, port: 5514), .init(kind: .syslog, transport: .udp, port: 5514)]
        c.internalNetworks = ["nope"]
        c.trustedResolvers = ["1.1.1.1", "bad"]
        c.allocation.flows = 0.9
        let e = c.validate()
        XCTAssertTrue(e.contains { $0.contains("5 GB and 500 GB") })
        XCTAssertTrue(e.contains { $0.contains("privileged") })
        XCTAssertTrue(e.contains { $0.contains("used by two listeners") })
        XCTAssertTrue(e.contains { $0.contains("Invalid internal network") })
        XCTAssertTrue(e.contains { $0.contains("Invalid resolver") })
        XCTAssertTrue(e.contains { $0.contains("allocation") })
        XCTAssertTrue(e.contains { $0.contains("Storage location") })
    }

    func testBudgetClampAndThreshold() {
        XCTAssertEqual(StorageBudget.clamp(1), StorageBudget.minimum)
        XCTAssertEqual(StorageBudget.clamp(.max), StorageBudget.maximum)
        var t = SafetyThreshold()
        XCTAssertEqual(t.bytes(forVolumeSize: 100_000_000_000), 10_000_000_000)   // 10 GB > 5 %
        XCTAssertEqual(t.bytes(forVolumeSize: 1_000_000_000_000), 50_000_000_000) // 5 % of 1 TB
        t.mode = .fixed; t.fixedBytes = 42
        XCTAssertEqual(t.bytes(forVolumeSize: 1), 42)
    }

    func testCodableRoundTrip() throws {
        let c = CollectorConfiguration(storageRoot: "/Volumes/X/NetSentry")
        let data = try JSONEncoder().encode(c)
        XCTAssertEqual(try JSONDecoder().decode(CollectorConfiguration.self, from: data), c)
    }
}

final class ConfigurationCompatibilityTests: XCTestCase {
    func testMissingKeysKeepDefaultsAndUnknownKeysAreIgnored() throws {
        let json = #"{"storageRoot":"/x","budgetBytes":50000000000,"futureKey":true,"privacy":{"externalLookupsEnabled":true}}"#
        let c = try JSONDecoder().decode(CollectorConfiguration.self, from: Data(json.utf8))
        XCTAssertEqual(c.storageRoot, "/x")
        XCTAssertEqual(c.budgetBytes, 50_000_000_000)
        XCTAssertEqual(c.listeners, ListenerConfiguration.defaults)
        XCTAssertTrue(c.privacy.externalLookupsEnabled)
        XCTAssertTrue(c.privacy.redactMACsInExports)
        XCTAssertFalse(c.diagnosticCapture.enabled)
    }

    func testEmptyObjectDecodes() throws {
        let c = try JSONDecoder().decode(CollectorConfiguration.self, from: Data("{}".utf8))
        XCTAssertEqual(c.budgetBytes, 25_000_000_000)
    }
}
