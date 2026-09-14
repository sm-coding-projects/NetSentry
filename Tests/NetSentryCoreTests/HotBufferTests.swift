import XCTest
@testable import NetSentryCore

final class HotBufferTests: XCTestCase {
    func testCountBoundAgeEvictionAndRangeQuery() {
        var b = HotBuffer<Int>(maxRecords: 5, maxAge: .seconds(10))
        for i in 0..<8 { b.append(i, at: Timestamp(seconds: 100 + Int64(i))) }
        XCTAssertEqual(b.count, 5)
        XCTAssertEqual(b.oldest, Timestamp(seconds: 103))
        let (recent, truncated) = b.query(from: Timestamp(seconds: 104), to: Timestamp(seconds: 106), limit: 10)
        XCTAssertEqual(recent, [6, 5, 4]); XCTAssertFalse(truncated)
        let (limited, t2) = b.query(from: Timestamp(seconds: 0), to: Timestamp(seconds: 200), limit: 2)
        XCTAssertEqual(limited, [7, 6]); XCTAssertTrue(t2)
        b.evict(now: Timestamp(seconds: 116))   // cutoff 106 → keeps 106, 107
        XCTAssertEqual(b.count, 2)
        XCTAssertEqual(b.query(from: Timestamp(seconds: 0), to: Timestamp(seconds: 200), limit: 10).records, [7, 6])
    }

    func testCompactionOfEvictedPrefixKeepsData() {
        var b = HotBuffer<Int>(maxRecords: 100_000, maxAge: .seconds(1))
        for i in 0..<20_000 { b.append(i, at: Timestamp(seconds: Int64(i))) }
        b.evict(now: Timestamp(seconds: 19_000))
        XCTAssertEqual(b.count, 1_001)
        XCTAssertEqual(b.query(from: Timestamp(seconds: 18_999), to: Timestamp(seconds: 18_999), limit: 1).records, [18_999])
    }
}
