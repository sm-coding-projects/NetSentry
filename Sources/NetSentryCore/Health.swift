import Foundation

public enum ListenerState: Codable, Sendable, Hashable {
    case stopped
    case starting
    case listening
    case failed(String)
    case disabled
    public var label: String {
        switch self {
        case .stopped: "Stopped"
        case .starting: "Starting"
        case .listening: "Listening"
        case .failed(let r): "Failed: \(r)"
        case .disabled: "Disabled"
        }
    }
}

public struct ListenerStatus: Codable, Sendable, Hashable, Identifiable {
    public var id: String { "\(kind.rawValue)-\(transport.rawValue)-\(port)" }
    public var kind: ListenerKind
    public var transport: Transport
    public var port: UInt16
    public var interface: String?      // nil = all interfaces
    public var state: ListenerState
    public var datagramsReceived: UInt64
    public var bytesReceived: UInt64
    public var lastPacketAt: Timestamp?
    public var lastSource: String?
    public var activeConnections: Int   // TCP only
    public init(kind: ListenerKind, transport: Transport, port: UInt16, interface: String?, state: ListenerState,
                datagramsReceived: UInt64 = 0, bytesReceived: UInt64 = 0, lastPacketAt: Timestamp? = nil,
                lastSource: String? = nil, activeConnections: Int = 0) {
        self.kind = kind; self.transport = transport; self.port = port; self.interface = interface; self.state = state
        self.datagramsReceived = datagramsReceived; self.bytesReceived = bytesReceived; self.lastPacketAt = lastPacketAt
        self.lastSource = lastSource; self.activeConnections = activeConnections
    }
}

public struct ExporterStatus: Codable, Sendable, Hashable, Identifiable {
    public var id: String { "\(kind.rawValue):\(key)" }
    public var kind: ListenerKind
    public var key: ExporterKey
    public var firstSeen: Timestamp
    public var lastSeen: Timestamp
    public var messages: UInt64
    public var records: UInt64
    public var lastSequence: UInt32?
    public var sequenceGaps: UInt64
    public var restarts: UInt64
    public var templates: Int
    public var pendingUndecodable: Int
    public var clockSkewMicroseconds: Int64?
    public init(kind: ListenerKind, key: ExporterKey, firstSeen: Timestamp, lastSeen: Timestamp, messages: UInt64 = 0,
                records: UInt64 = 0, lastSequence: UInt32? = nil, sequenceGaps: UInt64 = 0, restarts: UInt64 = 0,
                templates: Int = 0, pendingUndecodable: Int = 0, clockSkewMicroseconds: Int64? = nil) {
        self.kind = kind; self.key = key; self.firstSeen = firstSeen; self.lastSeen = lastSeen; self.messages = messages
        self.records = records; self.lastSequence = lastSequence; self.sequenceGaps = sequenceGaps; self.restarts = restarts
        self.templates = templates; self.pendingUndecodable = pendingUndecodable; self.clockSkewMicroseconds = clockSkewMicroseconds
    }
}

/// Monotonic counters for the whole pipeline. Every increment is attributable to one stage.
public struct PipelineCounters: Codable, Sendable, Hashable {
    public var datagramsReceived: UInt64 = 0
    public var bytesReceived: UInt64 = 0
    public var receiveQueueDropped: UInt64 = 0
    public var flowsDecoded: UInt64 = 0
    public var eventsDecoded: UInt64 = 0
    public var malformed: UInt64 = 0
    public var rejected: UInt64 = 0          // failed validation (e.g. exporter not allowed)
    public var missingTemplate: UInt64 = 0
    public var bufferedPendingTemplate: UInt64 = 0
    public var sequenceGaps: UInt64 = 0
    public var parserFailures: UInt64 = 0
    public var enriched: UInt64 = 0
    public var stored: UInt64 = 0
    public var storageWriteFailures: UInt64 = 0
    public var liveSampledOut: UInt64 = 0
    public init() {}
}

/// Instantaneous rates computed over a sliding window.
public struct PipelineRates: Codable, Sendable, Hashable {
    public var datagramsPerSecond: Double = 0
    public var flowsPerSecond: Double = 0
    public var eventsPerSecond: Double = 0
    public var bytesPerSecond: Double = 0
    public var failuresPerSecond: Double = 0
    public var windowSeconds: Double = 10
    public init() {}
}

public enum GapKind: String, Codable, Sendable {
    case collectorDown, listenerDown, sleep, receiveDrops, storagePause, diskPressure, clockChange, exporterSilent
    public var label: String {
        switch self {
        case .collectorDown: "Collector not running"
        case .listenerDown: "Listener down"
        case .sleep: "Mac asleep"
        case .receiveDrops: "Records dropped"
        case .storagePause: "Storage paused"
        case .diskPressure: "Disk pressure"
        case .clockChange: "System clock changed"
        case .exporterSilent: "Exporter silent"
        }
    }
}

/// A period during which collection is known or suspected to be incomplete.
/// A gap is never rendered as "no activity".
public struct CollectionGap: Codable, Sendable, Hashable, Identifiable {
    public var id: Int64
    public var start: Timestamp
    public var end: Timestamp?
    public var kind: GapKind
    public var reason: String
    public var details: [String: String]
    public init(id: Int64, start: Timestamp, end: Timestamp?, kind: GapKind, reason: String, details: [String: String] = [:]) {
        self.id = id; self.start = start; self.end = end; self.kind = kind; self.reason = reason; self.details = details
    }
    public var isOpen: Bool { end == nil }
}

public struct HealthWarning: Codable, Sendable, Hashable, Identifiable {
    public enum Level: String, Codable, Sendable { case info, warning, critical }
    public var id: String
    public var level: Level
    public var title: String
    public var detail: String
    public var since: Timestamp
    public init(id: String, level: Level, title: String, detail: String, since: Timestamp) {
        self.id = id; self.level = level; self.title = title; self.detail = detail; self.since = since
    }
}

public struct StorageSummary: Codable, Sendable, Hashable {
    public var root: String
    public var budgetBytes: Int64
    public var usedBytes: Int64
    public var usedByCategory: [String: Int64]
    public var freeBytesOnVolume: Int64
    public var safetyThresholdBytes: Int64
    public var oldestRecord: Timestamp?
    public var newestRecord: Timestamp?
    public var estimatedRetentionDays: Double?
    public var ingestionPaused: Bool
    public var segmentCount: Int
    public var integrityIssues: Int
    public var compactionInProgress: Bool
    public init(root: String, budgetBytes: Int64, usedBytes: Int64 = 0, usedByCategory: [String: Int64] = [:],
                freeBytesOnVolume: Int64 = 0, safetyThresholdBytes: Int64 = 0, oldestRecord: Timestamp? = nil,
                newestRecord: Timestamp? = nil, estimatedRetentionDays: Double? = nil, ingestionPaused: Bool = false,
                segmentCount: Int = 0, integrityIssues: Int = 0, compactionInProgress: Bool = false) {
        self.root = root; self.budgetBytes = budgetBytes; self.usedBytes = usedBytes; self.usedByCategory = usedByCategory
        self.freeBytesOnVolume = freeBytesOnVolume; self.safetyThresholdBytes = safetyThresholdBytes
        self.oldestRecord = oldestRecord; self.newestRecord = newestRecord; self.estimatedRetentionDays = estimatedRetentionDays
        self.ingestionPaused = ingestionPaused; self.segmentCount = segmentCount; self.integrityIssues = integrityIssues
        self.compactionInProgress = compactionInProgress
    }
}

/// Complete health picture the collector reports over IPC.
public struct HealthSnapshot: Codable, Sendable, Hashable {
    public var generatedAt: Timestamp
    public var collectorVersion: String
    public var collectorBuild: String
    public var startedAt: Timestamp
    public var pid: Int32
    public var listeners: [ListenerStatus]
    public var exporters: [ExporterStatus]
    public var counters: PipelineCounters
    public var rates: PipelineRates
    public var queues: [QueueStats]
    public var openGaps: [CollectionGap]
    public var warnings: [HealthWarning]
    public var storage: StorageSummary?
    public var demoWorkspace: Bool
    public init(generatedAt: Timestamp, collectorVersion: String, collectorBuild: String, startedAt: Timestamp, pid: Int32,
                listeners: [ListenerStatus], exporters: [ExporterStatus], counters: PipelineCounters, rates: PipelineRates,
                queues: [QueueStats], openGaps: [CollectionGap], warnings: [HealthWarning],
                storage: StorageSummary?, demoWorkspace: Bool) {
        self.generatedAt = generatedAt; self.collectorVersion = collectorVersion; self.collectorBuild = collectorBuild
        self.startedAt = startedAt; self.pid = pid; self.listeners = listeners; self.exporters = exporters
        self.counters = counters; self.rates = rates; self.queues = queues; self.openGaps = openGaps
        self.warnings = warnings; self.storage = storage; self.demoWorkspace = demoWorkspace
    }
}

