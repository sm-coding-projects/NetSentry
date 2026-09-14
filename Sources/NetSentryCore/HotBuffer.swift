import Foundation

/// Bounded in-memory ring of the most recent records for live views and "just now" investigation
/// queries. Eviction is by age and by count; both limits come from the configuration.
public struct HotBuffer<Element: Sendable>: Sendable {
    private var items: [(time: Timestamp, element: Element)] = []
    private var head = 0
    public let maxRecords: Int
    public let maxAge: Duration

    public init(maxRecords: Int, maxAge: Duration) {
        self.maxRecords = max(1, maxRecords)
        self.maxAge = maxAge
    }

    public var count: Int { items.count - head }

    public mutating func append(_ element: Element, at time: Timestamp) {
        items.append((time, element))
        if count > maxRecords { head += count - maxRecords }
        if head > 4_096, head * 2 > items.count { items.removeFirst(head); head = 0 }
    }

    /// Drops records older than `maxAge` relative to `now`.
    public mutating func evict(now: Timestamp) {
        let cutoff = now.microseconds - maxAge.microsecondsValue
        while head < items.count, items[head].time.microseconds < cutoff { head += 1 }
        if head > 4_096, head * 2 > items.count { items.removeFirst(head); head = 0 }
    }

    /// Records with time in [from, to], newest first, up to `limit`.
    public func query(from: Timestamp, to: Timestamp, limit: Int) -> (records: [Element], truncated: Bool) {
        var out: [Element] = []
        var i = items.count - 1
        while i >= head {
            let t = items[i].time
            if t <= to && t >= from {
                if out.count >= limit { return (out, true) }
                out.append(items[i].element)
            }
            i -= 1
        }
        return (out, false)
    }

    public var oldest: Timestamp? { head < items.count ? items[head].time : nil }
}
