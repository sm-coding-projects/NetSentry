import Foundation

/// UTC instant with microsecond precision, stored as microseconds since the Unix epoch.
public struct Timestamp: Hashable, Comparable, Codable, Sendable, CustomStringConvertible {
    public var microseconds: Int64

    public init(microseconds: Int64) { self.microseconds = microseconds }
    public init(seconds: Int64) { self.microseconds = seconds * 1_000_000 }
    public init(milliseconds: Int64) { self.microseconds = milliseconds * 1_000 }
    /// Clamped: a hostile or garbled date (year 99999999 from a fuzzed syslog header) must never trap the collector.
    public init(_ date: Date) {
        let micros = (date.timeIntervalSince1970 * 1_000_000).rounded()
        if micros.isNaN { self.microseconds = 0 }
        else { self.microseconds = Int64(max(min(micros, Double(Int64.max / 2)), Double(Int64.min / 2))) }
    }

    /// Wall clock now via `CLOCK_REALTIME`.
    public static var now: Timestamp {
        var ts = timespec()
        clock_gettime(CLOCK_REALTIME, &ts)
        return Timestamp(microseconds: Int64(ts.tv_sec) * 1_000_000 + Int64(ts.tv_nsec) / 1_000)
    }

    public var date: Date { Date(timeIntervalSince1970: Double(microseconds) / 1_000_000) }
    public var seconds: Int64 { microseconds / 1_000_000 }
    public var milliseconds: Int64 { microseconds / 1_000 }

    public static func < (lhs: Timestamp, rhs: Timestamp) -> Bool { lhs.microseconds < rhs.microseconds }
    public static func + (lhs: Timestamp, rhs: Duration) -> Timestamp {
        Timestamp(microseconds: lhs.microseconds + rhs.microsecondsValue)
    }
    public static func - (lhs: Timestamp, rhs: Timestamp) -> Duration {
        .microseconds(lhs.microseconds - rhs.microseconds)
    }
    /// Start of the containing bucket (minute/hour/day) in UTC.
    public func truncated(to bucket: Int64) -> Timestamp {
        Timestamp(microseconds: microseconds - (microseconds % bucket))
    }
    public var description: String { ISO8601DateFormatter.shared.string(from: date) }
}

public extension Duration {
    var microsecondsValue: Int64 {
        let c = components
        return c.seconds * 1_000_000 + c.attoseconds / 1_000_000_000_000
    }
}

extension ISO8601DateFormatter {
    nonisolated(unsafe) static let shared: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
}

/// Monotonic clock (survives wall-clock changes; used to detect clock jumps and measure rates).
public enum MonotonicClock {
    public static var nowNanoseconds: UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }
    /// Continues across sleep; used for gap detection.
    public static var continuousNanoseconds: UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC) }
}
