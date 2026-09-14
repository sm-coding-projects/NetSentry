import Foundation

/// Policy applied when a bounded queue is full.
public enum OverflowPolicy: Sendable {
    /// Reject the new element immediately (the producer must never block, e.g. the socket reader).
    case dropNewest
    /// Evict the oldest element to make room.
    case dropOldest
    /// Suspend the producer until space is available (backpressure).
    case suspend
}

public enum EnqueueResult: Sendable, Equatable { case accepted, droppedNewest, droppedOldest, closed }

/// Point-in-time statistics of any bounded queue (shared by the actor and lock-based variants).
public struct QueueStats: Sendable, Codable, Hashable {
    public var name: String
    public var depth: Int
    public var capacity: Int
    public var accepted: UInt64
    public var dropped: UInt64
    public var dequeued: UInt64
    public var highWatermark: Int
    public init(name: String, depth: Int, capacity: Int, accepted: UInt64, dropped: UInt64, dequeued: UInt64, highWatermark: Int) {
        self.name = name; self.depth = depth; self.capacity = capacity; self.accepted = accepted; self.dropped = dropped
        self.dequeued = dequeued; self.highWatermark = highWatermark
    }
    public var utilization: Double { capacity == 0 ? 0 : Double(depth) / Double(capacity) }
}

/// Bounded multi-producer / multi-consumer async queue backed by a ring buffer.
/// Every pipeline stage is joined by one of these; capacity and policy are explicit.
public actor BoundedQueue<Element: Sendable> {
    public let name: String
    public let capacity: Int
    public let policy: OverflowPolicy

    private var buffer: [Element?]
    private var head = 0
    private var count = 0
    private var closed = false
    private var waitingConsumers: [CheckedContinuation<Void, Never>] = []
    private var waitingProducers: [CheckedContinuation<Void, Never>] = []

    public private(set) var accepted: UInt64 = 0
    public private(set) var dropped: UInt64 = 0
    public private(set) var dequeued: UInt64 = 0
    public private(set) var highWatermark = 0

    public init(name: String, capacity: Int, policy: OverflowPolicy) {
        precondition(capacity > 0)
        self.name = name
        self.capacity = capacity
        self.policy = policy
        buffer = Array(repeating: nil, count: capacity)
    }

    public var depth: Int { count }
    public var isClosed: Bool { closed }

    public var stats: QueueStats {
        QueueStats(name: name, depth: count, capacity: capacity, accepted: accepted, dropped: dropped,
                   dequeued: dequeued, highWatermark: highWatermark)
    }

    @discardableResult
    public func enqueue(_ element: Element) async -> EnqueueResult {
        if closed { return .closed }
        if count == capacity {
            switch policy {
            case .dropNewest:
                dropped += 1
                return .droppedNewest
            case .dropOldest:
                head = (head + 1) % capacity
                count -= 1
                dropped += 1
                push(element)
                accepted += 1
                return .droppedOldest
            case .suspend:
                while count == capacity && !closed {
                    await withCheckedContinuation { waitingProducers.append($0) }
                }
                if closed { return .closed }
            }
        }
        push(element)
        accepted += 1
        return .accepted
    }

    /// Returns nil only after `close()` and the buffer has drained.
    public func dequeue() async -> Element? {
        while count == 0 {
            if closed { return nil }
            await withCheckedContinuation { waitingConsumers.append($0) }
        }
        return pop()
    }

    /// Dequeues up to `max` elements, waiting for at least one unless closed. Used for micro-batching.
    public func dequeueBatch(max: Int) async -> [Element] {
        while count == 0 {
            if closed { return [] }
            await withCheckedContinuation { waitingConsumers.append($0) }
        }
        var out: [Element] = []
        out.reserveCapacity(min(max, count))
        while count > 0 && out.count < max { out.append(pop()) }
        return out
    }

    /// Waits until either `max` elements are available or `maxWait` elapses (with at least one element),
    /// giving persistence stages a time-or-size bound.
    public func dequeueBatch(max: Int, maxWait: Duration) async -> [Element] {
        var out = await dequeueBatch(max: max)
        if out.count >= max || closed { return out }
        let deadline = ContinuousClock.now + maxWait
        while out.count < max, ContinuousClock.now < deadline {
            if count == 0 {
                try? await Task.sleep(for: .milliseconds(5))
                if Task.isCancelled { break }
                continue
            }
            while count > 0 && out.count < max { out.append(pop()) }
        }
        return out
    }

    public func close() {
        closed = true
        let c = waitingConsumers; waitingConsumers.removeAll()
        let p = waitingProducers; waitingProducers.removeAll()
        c.forEach { $0.resume() }
        p.forEach { $0.resume() }
    }

    private func push(_ element: Element) {
        buffer[(head + count) % capacity] = element
        count += 1
        highWatermark = max(highWatermark, count)
        if !waitingConsumers.isEmpty { waitingConsumers.removeFirst().resume() }
    }

    private func pop() -> Element {
        let e = buffer[head]!
        buffer[head] = nil
        head = (head + 1) % capacity
        count -= 1
        dequeued += 1
        if !waitingProducers.isEmpty { waitingProducers.removeFirst().resume() }
        return e
    }
}
