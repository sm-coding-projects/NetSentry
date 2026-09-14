import Foundation
import NetSentryCore

public struct Empty: Codable, Sendable, Hashable { public init() {} }

// MARK: - Requests

public struct StatusRequest: IPCRequest {
    public static let kind = "status.get"
    public typealias Reply = HealthSnapshot
    public init() {}
}

public struct ConfigGetRequest: IPCRequest {
    public static let kind = "config.get"
    public typealias Reply = CollectorConfiguration
    public init() {}
}

public struct ConfigApplyRequest: IPCRequest {
    public static let kind = "config.apply"
    public struct Reply: Codable, Sendable, Hashable {
        public var accepted: Bool
        public var errors: [String]
        public var restartedListeners: [String]
        public init(accepted: Bool, errors: [String], restartedListeners: [String]) {
            self.accepted = accepted; self.errors = errors; self.restartedListeners = restartedListeners
        }
    }
    public var configuration: CollectorConfiguration
    public init(configuration: CollectorConfiguration) { self.configuration = configuration }
}

/// Watches a listener for `seconds` and reports what arrived (setup wizard).
public struct ListenerTestRequest: IPCRequest {
    public static let kind = "listener.test"
    public struct Reply: Codable, Sendable, Hashable {
        public var kind: ListenerKind
        public var listening: Bool
        public var packets: UInt64
        public var bytes: UInt64
        public var sources: [String]
        public var templatesSeen: Int
        public var recordsDecoded: UInt64
        public var errors: [String]
        public init(kind: ListenerKind, listening: Bool, packets: UInt64, bytes: UInt64, sources: [String],
                    templatesSeen: Int, recordsDecoded: UInt64, errors: [String]) {
            self.kind = kind; self.listening = listening; self.packets = packets; self.bytes = bytes; self.sources = sources
            self.templatesSeen = templatesSeen; self.recordsDecoded = recordsDecoded; self.errors = errors
        }
    }
    public var kind: ListenerKind
    public var seconds: Int
    public init(kind: ListenerKind, seconds: Int) { self.kind = kind; self.seconds = min(max(seconds, 1), 120) }
}

public struct LiveFilter: Codable, Sendable, Hashable {
    public var flows = true
    public var events = true
    public var clientIP: String?
    public var text: String?
    public init() {}
}

public struct LiveSubscribeRequest: IPCRequest {
    public static let kind = "live.subscribe"
    public struct Reply: Codable, Sendable, Hashable {
        public var subscriptionID: UUID
        public init(subscriptionID: UUID) { self.subscriptionID = subscriptionID }
    }
    public var filter: LiveFilter
    public var maxPerSecond: Int
    public init(filter: LiveFilter, maxPerSecond: Int) { self.filter = filter; self.maxPerSecond = maxPerSecond }
}

public struct LiveUnsubscribeRequest: IPCRequest {
    public static let kind = "live.unsubscribe"
    public typealias Reply = Empty
    public var subscriptionID: UUID
    public init(subscriptionID: UUID) { self.subscriptionID = subscriptionID }
}

public struct HotQueryRequest: IPCRequest {
    public static let kind = "hot.query"
    public struct Reply: Codable, Sendable {
        public var flows: [FlowRecord]
        public var events: [SyslogEvent]
        public var truncated: Bool
        public init(flows: [FlowRecord], events: [SyslogEvent], truncated: Bool) {
            self.flows = flows; self.events = events; self.truncated = truncated
        }
    }
    public var start: Timestamp
    public var end: Timestamp
    public var filter: LiveFilter
    public var limit: Int
    public init(start: Timestamp, end: Timestamp, filter: LiveFilter, limit: Int) {
        self.start = start; self.end = end; self.filter = filter; self.limit = min(max(limit, 1), 20_000)
    }
}

public struct StorageStatusRequest: IPCRequest {
    public static let kind = "storage.status"
    public typealias Reply = StorageSummary
    public init() {}
}

public struct RetentionPreviewRequest: IPCRequest {
    public static let kind = "retention.preview"
    public struct Reply: Codable, Sendable, Hashable {
        public struct Step: Codable, Sendable, Hashable {
            public var stage: Int; public var description: String; public var bytesFreed: Int64; public var segments: Int
            public var oldestSurvivingFlow: Timestamp?; public var oldestSurvivingEvent: Timestamp?
            public init(stage: Int, description: String, bytesFreed: Int64, segments: Int, oldestSurvivingFlow: Timestamp?, oldestSurvivingEvent: Timestamp?) {
                self.stage = stage; self.description = description; self.bytesFreed = bytesFreed; self.segments = segments
                self.oldestSurvivingFlow = oldestSurvivingFlow; self.oldestSurvivingEvent = oldestSurvivingEvent
            }
        }
        public var budgetBytes: Int64; public var usageBefore: Int64; public var usageAfter: Int64; public var steps: [Step]; public var removesRecentData: Bool
        public init(budgetBytes: Int64, usageBefore: Int64, usageAfter: Int64, steps: [Step], removesRecentData: Bool) {
            self.budgetBytes = budgetBytes; self.usageBefore = usageBefore; self.usageAfter = usageAfter; self.steps = steps; self.removesRecentData = removesRecentData
        }
    }
    public var budgetBytes: Int64
    public init(budgetBytes: Int64) { self.budgetBytes = budgetBytes }
}

public struct RetentionRunRequest: IPCRequest {
    public static let kind = "retention.run"
    public typealias Reply = StorageSummary
    public init() {}
}

public struct SegmentsVerifyRequest: IPCRequest {
    public static let kind = "segments.verify"
    public struct Reply: Codable, Sendable, Hashable { public var issues: [String]; public init(issues: [String]) { self.issues = issues } }
    public var segmentIDs: [Int64]?
    public init(segmentIDs: [Int64]? = nil) { self.segmentIDs = segmentIDs }
}

public struct StorageFlushRequest: IPCRequest {
    public static let kind = "storage.flush"
    public typealias Reply = StorageSummary
    public init() {}
}

// MARK: - Security & entities (payloads are generic JSON so IPC stays independent of the detection package)

/// Generic request routed to the collector's security/entity handler; `op` selects the operation.
public struct SecurityRequest: IPCRequest {
    public static let kind = "security.op"
    public struct Reply: Codable, Sendable { public var json: Data; public init(json: Data) { self.json = json } }
    public var op: String
    public var args: [String: String]
    public init(op: String, args: [String: String] = [:]) { self.op = op; self.args = args }
}

public struct AlertRaised: IPCNotification, Hashable {
    public static let kind = "alert.raised"
    public var id: Int64; public var title: String; public var summary: String; public var severity: AlertSeverity; public var isNew: Bool; public var clientID: Int64?
    /// True when the collector already posted a user notification for this alert (so the dashboard must not repeat it).
    public var notified: Bool
    public init(id: Int64, title: String, summary: String, severity: AlertSeverity, isNew: Bool, clientID: Int64?, notified: Bool) {
        self.id = id; self.title = title; self.summary = summary; self.severity = severity; self.isNew = isNew; self.clientID = clientID; self.notified = notified
    }
}

/// Consistent backup of the manifest (SQLite online backup) plus the configuration file, zipped under <Store>/backups.
public struct StorageBackupRequest: IPCRequest {
    public static let kind = "storage.backup"
    public struct Reply: Codable, Sendable { public var path: String; public var bytes: Int64; public init(path: String, bytes: Int64) { self.path = path; self.bytes = bytes } }
    public init() {}
}

public struct DiagnosticsExportRequest: IPCRequest {
    public static let kind = "diagnostics.export"
    public struct Reply: Codable, Sendable { public var path: String; public init(path: String) { self.path = path } }
    public var includeTelemetry: Bool
    public init(includeTelemetry: Bool) { self.includeTelemetry = includeTelemetry }
}

public struct GracefulShutdownRequest: IPCRequest {
    public static let kind = "shutdown.graceful"
    public typealias Reply = Empty
    public init() {}
}

// MARK: - Notifications (collector → dashboard)

public struct LiveBatch: IPCNotification {
    public static let kind = "live.batch"
    public var subscriptionID: UUID
    public var flows: [FlowRecord]
    public var events: [SyslogEvent]
    public var sampledOut: Int
    public var generatedAt: Timestamp
    public init(subscriptionID: UUID, flows: [FlowRecord], events: [SyslogEvent], sampledOut: Int, generatedAt: Timestamp) {
        self.subscriptionID = subscriptionID; self.flows = flows; self.events = events; self.sampledOut = sampledOut; self.generatedAt = generatedAt
    }
}

public struct HealthChanged: IPCNotification {
    public static let kind = "health.changed"
    public var snapshot: HealthSnapshot
    public init(snapshot: HealthSnapshot) { self.snapshot = snapshot }
}

public struct StorageWarningNotification: IPCNotification {
    public static let kind = "storage.warning"
    public var level: HealthWarning.Level
    public var reason: String
    public var freeBytes: Int64
    public var budgetBytes: Int64
    public init(level: HealthWarning.Level, reason: String, freeBytes: Int64, budgetBytes: Int64) {
        self.level = level; self.reason = reason; self.freeBytes = freeBytes; self.budgetBytes = budgetBytes
    }
}
