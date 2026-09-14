import Foundation
import NetSentryCore

/// Typed, composable filter model. Views build these; the engine compiles them to parameterized SQL.
/// No user-entered string ever reaches SQL text: values are bound, identifiers come from fixed enums.
public struct TimeRange: Sendable, Hashable, Codable {
    public var start: Timestamp
    public var end: Timestamp
    public init(start: Timestamp, end: Timestamp) { self.start = start; self.end = end }
    public static func last(_ d: Duration, now: Timestamp = .now) -> TimeRange { TimeRange(start: Timestamp(microseconds: now.microseconds - d.microsecondsValue), end: now) }
    public var duration: Duration { end - start }
}

public enum FlowSortKey: String, Sendable, Codable, CaseIterable { case startTime = "start_time", endTime = "end_time", octets, packets, srcIP = "src_ip", dstIP = "dst_ip", dstPort = "dst_port", protocolNumber = "protocol", duration = "(end_time - start_time)" }
public enum EventSortKey: String, Sendable, Codable, CaseIterable { case receivedAt = "received_at", eventTime = "event_time", severity, eventType = "event_type", srcIP = "src_ip", dstIP = "dst_ip" }
public enum SortDirection: String, Sendable, Codable { case ascending = "ASC", descending = "DESC" }

/// Filters shared by flow and event queries. `nil` means "no constraint".
public struct RecordFilter: Sendable, Hashable, Codable {
    public var range: TimeRange
    public var anyIP: IPAddress?            // src OR dst
    public var srcIP: IPAddress?
    public var dstIP: IPAddress?
    public var prefix: IPPrefix?            // src OR dst within prefix (IPv4 only via v4 columns)
    public var clientID: Int64?             // src_client_id OR dst_client_id
    public var ports: [UInt16] = []         // dst_port IN (…)
    public var protocols: [UInt8] = []
    public var directions: [TrafficDirection] = []
    public var countries: [String] = []
    public var asns: [UInt32] = []
    public var vlans: [UInt16] = []
    public var exporterAddress: IPAddress?
    public var minOctets: UInt64?
    public var minPackets: UInt64?
    public var actions: [FirewallAction] = []            // events only
    public var severities: [SyslogSeverity] = []         // events only
    public var eventTypes: [EventType] = []              // events only
    public var idsSignature: String?                     // events only, substring
    public var text: String?                             // events: message substring; flows: ignored
    public var origin: Origin = .live
    public init(range: TimeRange) { self.range = range }
}

public struct FlowQuery: Sendable, Hashable, Codable {
    public var filter: RecordFilter
    public var sort: FlowSortKey = .startTime
    public var direction: SortDirection = .descending
    public var limit: Int = 500
    /// Keyset cursor: (sort value, flow_id) of the last row of the previous page.
    public var after: (Int64, Int64)? { get { cursor.map { ($0.value, $0.id) } } set { cursor = newValue.map { Cursor(value: $0.0, id: $0.1) } } }
    public var cursor: Cursor?
    public struct Cursor: Sendable, Hashable, Codable { public var value: Int64; public var id: Int64; public init(value: Int64, id: Int64) { self.value = value; self.id = id } }
    public init(filter: RecordFilter) { self.filter = filter }
}

public struct EventQuery: Sendable, Hashable, Codable {
    public var filter: RecordFilter
    public var sort: EventSortKey = .receivedAt
    public var direction: SortDirection = .descending
    public var limit: Int = 500
    public var cursor: FlowQuery.Cursor?
    public init(filter: RecordFilter) { self.filter = filter }
}

/// Dimension for top-N and grouped aggregations.
public enum GroupDimension: String, Sendable, Codable, CaseIterable {
    case srcIP = "src_ip", dstIP = "dst_ip", dstPort = "dst_port", protocolNumber = "protocol", dstCountry = "dst_country", dstASN = "dst_asn", dstOrg = "dst_org",
         service, direction, srcClient = "src_client_id", dstClient = "dst_client_id", exporter = "exporter_addr"
}

public struct TopNQuery: Sendable, Hashable, Codable {
    public var filter: RecordFilter
    public var dimension: GroupDimension
    public var limit: Int = 20
    public init(filter: RecordFilter, dimension: GroupDimension, limit: Int = 20) { self.filter = filter; self.dimension = dimension; self.limit = limit }
}

public struct TopNRow: Sendable, Hashable, Codable, Identifiable {
    public var id: String { key }
    public var key: String
    public var flows: Int64
    public var bytes: Int64
    public var packets: Int64
    public init(key: String, flows: Int64, bytes: Int64, packets: Int64) { self.key = key; self.flows = flows; self.bytes = bytes; self.packets = packets }
}

public struct TimeBucket: Sendable, Hashable, Codable, Identifiable {
    public var id: Int64 { bucket.microseconds }
    public var bucket: Timestamp
    public var flows: Int64
    public var bytes: Int64
    public var packets: Int64
    public var inboundBytes: Int64
    public var outboundBytes: Int64
    public init(bucket: Timestamp, flows: Int64, bytes: Int64, packets: Int64, inboundBytes: Int64, outboundBytes: Int64) {
        self.bucket = bucket; self.flows = flows; self.bytes = bytes; self.packets = packets; self.inboundBytes = inboundBytes; self.outboundBytes = outboundBytes
    }
}

public struct EventCountRow: Sendable, Hashable, Codable, Identifiable {
    public var id: String { key }
    public var key: String
    public var count: Int64
    public init(key: String, count: Int64) { self.key = key; self.count = count }
}

public struct QueryPage<Row: Sendable & Codable & Hashable>: Sendable, Codable, Hashable {
    public var rows: [Row]
    public var nextCursor: FlowQuery.Cursor?
    public var segmentsScanned: Int
    public var elapsed: Duration
    public init(rows: [Row], nextCursor: FlowQuery.Cursor?, segmentsScanned: Int, elapsed: Duration) { self.rows = rows; self.nextCursor = nextCursor; self.segmentsScanned = segmentsScanned; self.elapsed = elapsed }
}
