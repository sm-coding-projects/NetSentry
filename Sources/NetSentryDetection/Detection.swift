import Foundation
import NetSentryCore
import NetSentryPersistence

/// One detection outcome. The engine turns findings into alerts (deduplicated by `dedupeKey`).
public struct Finding: Sendable, Hashable {
    public var ruleName: String
    public var ruleVersion: Int
    public var severity: AlertSeverity
    public var title: String
    public var summary: String
    public var explanation: String            // Markdown: why it triggered, with numbers
    public var occurredAt: Timestamp
    public var clientID: Int64?
    public var entity: Entity
    public var evidence: [String: String]     // metrics and observed values
    public var baseline: Baseline?
    public var flowIDs: [Int64]
    public var eventIDs: [Int64]
    public var steps: [String]
    public var dedupeKey: String

    public struct Entity: Sendable, Hashable, Codable {
        public var kind: String   // client | ip | asn | country | port | exporter | vlan | collector
        public var id: String
        public var label: String
        public init(kind: String, id: String, label: String) { self.kind = kind; self.id = id; self.label = label }
    }
    public struct Baseline: Sendable, Hashable, Codable {
        public var kind: String   // threshold | rolling
        public var value: Double
        public var unit: String
        public var period: String
        public var samples: Int
        public init(kind: String, value: Double, unit: String, period: String, samples: Int) { self.kind = kind; self.value = value; self.unit = unit; self.period = period; self.samples = samples }
    }

    public init(ruleName: String, ruleVersion: Int, severity: AlertSeverity, title: String, summary: String, explanation: String, occurredAt: Timestamp, clientID: Int64?,
                entity: Entity, evidence: [String: String], baseline: Baseline? = nil, flowIDs: [Int64] = [], eventIDs: [Int64] = [], steps: [String], dedupeKey: String) {
        self.ruleName = ruleName; self.ruleVersion = ruleVersion; self.severity = severity; self.title = title; self.summary = summary; self.explanation = explanation
        self.occurredAt = occurredAt; self.clientID = clientID; self.entity = entity; self.evidence = evidence; self.baseline = baseline; self.flowIDs = flowIDs
        self.eventIDs = eventIDs; self.steps = steps; self.dedupeKey = dedupeKey
    }
}

/// A user-tunable parameter with its default; the UI renders these generically.
public struct RuleParameter: Sendable, Hashable, Codable {
    public var key: String
    public var label: String
    public var value: Double
    public var unit: String
    public var help: String
    public init(key: String, label: String, value: Double, unit: String, help: String) { self.key = key; self.label = label; self.value = value; self.unit = unit; self.help = help }
}

public struct RuleConfiguration: Sendable, Hashable, Codable {
    public var enabled = true
    public var parameters: [String: Double] = [:]
    public init() {}
}

/// Everything a rule may consult while evaluating a batch. Rules never touch the UI or IPC.
public struct DetectionContext: Sendable {
    public var now: Timestamp
    public var configuration: RuleConfiguration
    public var trustedResolvers: Set<IPAddress>
    public var internalPrefixes: [IPPrefix]
    public var clientName: @Sendable (Int64) -> String
    public var expected: @Sendable (_ scopeType: String, _ scopeValue: String, _ kind: String, _ value: String) -> Bool
    public init(now: Timestamp, configuration: RuleConfiguration, trustedResolvers: Set<IPAddress>, internalPrefixes: [IPPrefix],
                clientName: @escaping @Sendable (Int64) -> String, expected: @escaping @Sendable (String, String, String, String) -> Bool) {
        self.now = now; self.configuration = configuration; self.trustedResolvers = trustedResolvers; self.internalPrefixes = internalPrefixes; self.clientName = clientName; self.expected = expected
    }
    public func param(_ key: String, _ rule: any DetectionRule) -> Double {
        configuration.parameters[key] ?? rule.parameters.first { $0.key == key }?.value ?? 0
    }
    public func isInternal(_ ip: IPAddress) -> Bool { ip.isPrivate || ip.isLinkLocal || internalPrefixes.contains { $0.contains(ip) } }
}

/// Persistent, rule-scoped key/value state (SQLite `rule_state`) plus first-seen and baseline tables.
public protocol RuleStateStore: Sendable {
    func get(rule: String, key: String) throws -> String?
    func set(rule: String, key: String, value: String) throws
    /// Records a (scope, kind, key) observation; returns true when it was never seen before.
    func firstSeen(scopeType: String, scopeValue: String, kind: String, key: String, at: Timestamp) throws -> Bool
    /// Hourly outbound bytes per client for the trailing window, oldest first (from rollups).
    func hourlyOutboundBytes(clientID: Int64, hours: Int, before: Timestamp) throws -> [Int64]
    /// Hour-of-day activity histogram for a client over the trailing days (24 buckets, flow counts).
    func hourOfDayHistogram(clientID: Int64, days: Int, before: Timestamp) throws -> [Int64]
}

public protocol DetectionRule: Sendable {
    var name: String { get }
    var version: Int { get }
    var title: String { get }
    var description: String { get }
    var defaultSeverity: AlertSeverity { get }
    var parameters: [RuleParameter] { get }
    /// Evaluates one enriched batch. Rules are called sequentially; they may keep in-memory windows.
    mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding]
    /// Periodic evaluation for time-window rules (called every `tickInterval`); default no-op.
    mutating func tick(context: DetectionContext, state: any RuleStateStore) throws -> [Finding]
}

public extension DetectionRule {
    mutating func tick(context: DetectionContext, state: any RuleStateStore) throws -> [Finding] { [] }
}

/// Helpers shared by rules.
enum Fmt {
    static func bytes(_ b: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(clamping: b), countStyle: .file) }
    static func bytes(_ b: Int64) -> String { ByteCountFormatter.string(fromByteCount: b, countStyle: .file) }
    static func ratio(_ a: Double, _ b: Double) -> String { b > 0 ? String(format: "%.1f×", a / b) : "∞" }
    static func time(_ t: Timestamp) -> String { t.date.formatted(date: .abbreviated, time: .shortened) }
}
