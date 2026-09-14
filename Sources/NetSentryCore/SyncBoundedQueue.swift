import Foundation
import os

/// Lock-based bounded queue for the socket → decode hand-off. Producers never suspend and never
/// block for longer than the lock; when full the newest element is dropped and counted.
/// Consumers drain batches asynchronously.
public final class SyncBoundedQueue<Element: Sendable>: @unchecked Sendable {
    public let name: String
    public let capacity: Int

    private struct State {
        var buffer: [Element?]
        var head = 0
        var count = 0
        var closed = false
        var accepted: UInt64 = 0
        var dropped: UInt64 = 0
        var dequeued: UInt64 = 0
        var highWatermark = 0
        var waiter: CheckedContinuation<Void, Never>?
    }

    private let state: OSAllocatedUnfairLock<State>

    public init(name: String, capacity: Int) {
        precondition(capacity > 0)
        self.name = name
        self.capacity = capacity
        state = OSAllocatedUnfairLock(initialState: State(buffer: Array(repeating: nil, count: capacity)))
    }

    /// Returns false when the element was dropped (queue full or closed).
    @discardableResult
    public func enqueue(_ element: Element) -> Bool {
        let (ok, waiter): (Bool, CheckedContinuation<Void, Never>?) = state.withLock { s in
            if s.closed || s.count == s.buffer.count {
                s.dropped += 1
                return (false, nil)
            }
            s.buffer[(s.head + s.count) % s.buffer.count] = element
            s.count += 1
            s.accepted += 1
            s.highWatermark = max(s.highWatermark, s.count)
            let w = s.waiter
            s.waiter = nil
            return (true, w)
        }
        waiter?.resume()
        return ok
    }

    /// Waits for at least one element (or close), then returns up to `max` elements.
    public func dequeueBatch(max: Int) async -> [Element] {
        while true {
            let (batch, closed): ([Element], Bool) = state.withLock { s in
                if s.count == 0 { return ([], s.closed) }
                var out: [Element] = []
                out.reserveCapacity(min(max, s.count))
                while s.count > 0 && out.count < max {
                    out.append(s.buffer[s.head]!)
                    s.buffer[s.head] = nil
                    s.head = (s.head + 1) % s.buffer.count
                    s.count -= 1
                    s.dequeued += 1
                }
                return (out, s.closed)
            }
            if !batch.isEmpty || closed { return batch }
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                let resumeNow: Bool = state.withLock { s in
                    if s.count > 0 || s.closed { return true }
                    s.waiter?.resume()  // should not happen: single consumer
                    s.waiter = c
                    return false
                }
                if resumeNow { c.resume() }
            }
        }
    }

    public func close() {
        let w: CheckedContinuation<Void, Never>? = state.withLock { s in
            s.closed = true
            let w = s.waiter
            s.waiter = nil
            return w
        }
        w?.resume()
    }

    public var stats: QueueStats {
        state.withLock { s in
            QueueStats(name: name, depth: s.count, capacity: capacity, accepted: s.accepted, dropped: s.dropped,
                       dequeued: s.dequeued, highWatermark: s.highWatermark)
        }
    }
}

/// A datagram or TCP-framed message exactly as received, stamped at the socket.
public struct RawDatagram: Sendable {
    public var receivedAt: Timestamp
    public var kind: ListenerKind
    public var transport: Transport
    public var source: IPAddress
    public var sourcePort: UInt16
    public var localPort: UInt16
    public var payload: Data
    public init(receivedAt: Timestamp, kind: ListenerKind, transport: Transport, source: IPAddress, sourcePort: UInt16, localPort: UInt16, payload: Data) {
        self.receivedAt = receivedAt; self.kind = kind; self.transport = transport; self.source = source
        self.sourcePort = sourcePort; self.localPort = localPort; self.payload = payload
    }
}
