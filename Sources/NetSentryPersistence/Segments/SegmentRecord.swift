import Foundation
import NetSentryCore

/// Manifest row for one Parquet segment.
public struct SegmentRecord: Sendable, Hashable, Codable, Identifiable {
    public var id: Int64
    public var kind: SegmentKind
    public var tier: SegmentTier
    public var start: Timestamp
    public var end: Timestamp
    public var path: String            // relative to the storage root
    public var rowCount: Int64
    public var bytes: Int64
    public var rawBytes: Int64
    public var compacted: Bool
    public var state: SegmentState
    public var schemaVersion: Int
    public var enrichmentVersion: Int
    public var parserVersions: String?
    public var sha256: String?
    public var createdAt: Timestamp
    public var finalizedAt: Timestamp?
    public var origin: Origin

    public init(id: Int64 = 0, kind: SegmentKind, tier: SegmentTier, start: Timestamp, end: Timestamp, path: String, rowCount: Int64, bytes: Int64,
                rawBytes: Int64 = 0, compacted: Bool = false, state: SegmentState, schemaVersion: Int, enrichmentVersion: Int, parserVersions: String? = nil,
                sha256: String? = nil, createdAt: Timestamp, finalizedAt: Timestamp? = nil, origin: Origin = .live) {
        self.id = id; self.kind = kind; self.tier = tier; self.start = start; self.end = end; self.path = path; self.rowCount = rowCount; self.bytes = bytes
        self.rawBytes = rawBytes; self.compacted = compacted; self.state = state; self.schemaVersion = schemaVersion; self.enrichmentVersion = enrichmentVersion
        self.parserVersions = parserVersions; self.sha256 = sha256; self.createdAt = createdAt; self.finalizedAt = finalizedAt; self.origin = origin
    }
}

/// Column statistics recorded per segment for query pruning.
public struct SegmentColumnStats: Sendable, Hashable, Codable {
    public var column: String
    public var min: Int64?
    public var max: Int64?
    public var distinctEstimate: Int64?
    public init(column: String, min: Int64?, max: Int64?, distinctEstimate: Int64? = nil) {
        self.column = column; self.min = min; self.max = max; self.distinctEstimate = distinctEstimate
    }
}
