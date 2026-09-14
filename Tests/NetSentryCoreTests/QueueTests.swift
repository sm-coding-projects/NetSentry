import XCTest
@testable import NetSentryCore

final class QueueTests: XCTestCase {
    func testDropNewestCountsDrops() async {
        let q = BoundedQueue<Int>(name: "t", capacity: 2, policy: .dropNewest)
        let r1 = await q.enqueue(1), r2 = await q.enqueue(2), r3 = await q.enqueue(3)
        XCTAssertEqual([r1, r2, r3], [.accepted, .accepted, .droppedNewest])
        let s = await q.stats
        XCTAssertEqual(s.dropped, 1); XCTAssertEqual(s.depth, 2); XCTAssertEqual(s.highWatermark, 2)
        let a = await q.dequeue(); let b = await q.dequeue()
        XCTAssertEqual([a, b], [1, 2])
    }

    func testDropOldestKeepsNewest() async {
        let q = BoundedQueue<Int>(name: "t", capacity: 2, policy: .dropOldest)
        await q.enqueue(1); await q.enqueue(2)
        let r = await q.enqueue(3)
        XCTAssertEqual(r, .droppedOldest)
        let batch = await q.dequeueBatch(max: 10)
        XCTAssertEqual(batch, [2, 3])
    }

    func testSuspendAppliesBackpressure() async {
        let q = BoundedQueue<Int>(name: "t", capacity: 1, policy: .suspend)
        await q.enqueue(1)
        let producer = Task { await q.enqueue(2) }
        try? await Task.sleep(for: .milliseconds(50))
        let depthBefore = await q.depth
        XCTAssertEqual(depthBefore, 1)
        let first = await q.dequeue()
        XCTAssertEqual(first, 1)
        let r = await producer.value
        XCTAssertEqual(r, .accepted)
        let second = await q.dequeue()
        XCTAssertEqual(second, 2)
    }

    func testCloseDrainsThenReturnsNil() async {
        let q = BoundedQueue<Int>(name: "t", capacity: 4, policy: .dropNewest)
        await q.enqueue(7)
        await q.close()
        let a = await q.dequeue(), b = await q.dequeue(), r = await q.enqueue(8)
        XCTAssertEqual(a, 7); XCTAssertNil(b); XCTAssertEqual(r, .closed)
    }

    func testSyncQueueProducerConsumer() async {
        let q = SyncBoundedQueue<Int>(name: "receive", capacity: 100)
        let consumer = Task { () -> Int in
            var total = 0
            while true {
                let b = await q.dequeueBatch(max: 32)
                if b.isEmpty { return total }
                total += b.count
            }
        }
        var accepted = 0
        for i in 0..<1_000 {
            if q.enqueue(i) { accepted += 1 }
            if i % 50 == 0 { try? await Task.sleep(for: .milliseconds(1)) }
        }
        q.close()
        let consumed = await consumer.value
        XCTAssertEqual(consumed, accepted)
        XCTAssertEqual(q.stats.accepted, UInt64(accepted))
        XCTAssertEqual(q.stats.dropped, UInt64(1_000 - accepted))
    }

    func testSyncQueueDropsWhenFull() {
        let q = SyncBoundedQueue<Int>(name: "r", capacity: 3)
        XCTAssertTrue(q.enqueue(1)); XCTAssertTrue(q.enqueue(2)); XCTAssertTrue(q.enqueue(3))
        XCTAssertFalse(q.enqueue(4))
        XCTAssertEqual(q.stats.dropped, 1)
        XCTAssertEqual(q.stats.depth, 3)
    }
}
