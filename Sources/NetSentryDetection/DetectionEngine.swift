import Foundation
import NetSentryCore
import NetSentryPersistence
import os

/// Runs every enabled rule over enriched batches, applies suppressions/expectations, and records alerts.
/// Independent of UI and IPC: the owner receives new alerts through `onAlert`.
public actor DetectionEngine {
    public static func defaultRules() -> [any DetectionRule] {
        [FirstSeenRule(kind: .destination), FirstSeenRule(kind: .country), FirstSeenRule(kind: .asn), FirstSeenRule(kind: .service),
         UnauthorizedResolverRule(), PortScanRule(kind: .horizontal), PortScanRule(kind: .vertical), RepeatedDenialsRule(),
         LargeOutboundTransferRule(), UnusualVolumeRule(), UnusualTimeRule(), BeaconingRule(), UnexpectedVLANRule(), IDSCorrelationRule(), CollectionFailureRule()]
    }

    public struct Stats: Sendable, Hashable, Codable {
        public var batches = 0
        public var findings = 0
        public var suppressed = 0
        public var alertsCreated = 0
        public var alertsUpdated = 0
        public var ruleErrors: [String: Int] = [:]
        public init() {}
    }

    private var rules: [any DetectionRule]
    private let alerts: AlertStore
    private let state: SQLiteRuleState
    private let log = Log.logger("detection", process: "collector")
    private var configurations: [String: RuleConfiguration] = [:]
    private var suppressions: [Suppression] = []
    private var expectations: Set<String> = []
    private var trustedResolvers: Set<IPAddress> = []
    private var internalPrefixes: [IPPrefix] = []
    private var clientNames: [Int64: String] = [:]
    private var lastHealth: HealthSnapshot?
    private var origin: Origin = .live
    public private(set) var stats = Stats()
    public var onAlert: (@Sendable (Alert, Bool) -> Void)?

    public init(meta: MetaStore, rules: [any DetectionRule] = DetectionEngine.defaultRules()) async throws {
        self.rules = rules
        alerts = AlertStore(meta: meta)
        state = SQLiteRuleState(meta: meta)
        try await reloadPolicy()
        // Persist default configurations so the UI can show every rule with its parameters.
        for r in rules where configurations[r.name] == nil {
            var c = RuleConfiguration(); c.parameters = Dictionary(uniqueKeysWithValues: r.parameters.map { ($0.key, $0.value) })
            try await alerts.setRuleConfiguration(r.name, version: r.version, c); configurations[r.name] = c
        }
    }

    public var alertStore: AlertStore { alerts }
    public var ruleDescriptors: [(name: String, version: Int, title: String, description: String, severity: AlertSeverity, parameters: [RuleParameter])] {
        rules.map { ($0.name, $0.version, $0.title, $0.description, $0.defaultSeverity, $0.parameters) }
    }

    public func configure(trustedResolvers: [IPAddress], internalPrefixes: [IPPrefix], origin: Origin) {
        self.trustedResolvers = Set(trustedResolvers); self.internalPrefixes = internalPrefixes; self.origin = origin
    }
    public func setClientName(_ id: Int64, _ name: String) { clientNames[id] = name }
    public func setOnAlert(_ cb: @escaping @Sendable (Alert, Bool) -> Void) { onAlert = cb }

    /// Reloads rule configurations, suppressions and expectations from SQLite (after user edits).
    public func reloadPolicy() async throws {
        configurations = try await alerts.ruleConfigurations()
        suppressions = try await alerts.suppressions()
        expectations = try await alerts.expectationSet()
    }

    private func context(now: Timestamp, for rule: any DetectionRule) -> DetectionContext {
        let names = clientNames, exp = expectations
        return DetectionContext(now: now, configuration: configurations[rule.name] ?? RuleConfiguration(), trustedResolvers: trustedResolvers, internalPrefixes: internalPrefixes,
                                clientName: { names[$0] ?? "client \($0)" },
                                expected: { exp.contains("\($0)|\($1)|\($2)|\($3)") })
    }

    /// Evaluates one enriched batch; returns the alerts that were created or updated.
    @discardableResult
    public func evaluate(flows: [FlowRecord], events: [SyslogEvent], now: Timestamp = .now) async -> [Alert] {
        stats.batches += 1
        var out: [Alert] = []
        for i in rules.indices {
            let ctx = context(now: now, for: rules[i])
            guard ctx.configuration.enabled else { continue }
            do {
                let findings = try rules[i].evaluate(flows: flows, events: events, context: ctx, state: state)
                out += await record(findings, now: now)
            } catch {
                stats.ruleErrors[rules[i].name, default: 0] += 1
                log.error("rule \(self.rules[i].name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            }
        }
        return out
    }

    /// Health-based detections (called with each health snapshot).
    public func evaluate(health: HealthSnapshot) async -> [Alert] {
        defer { lastHealth = health }
        guard let rule = rules.first(where: { $0 is CollectionFailureRule }) as? CollectionFailureRule else { return [] }
        let ctx = context(now: health.generatedAt, for: rule)
        guard ctx.configuration.enabled else { return [] }
        return await record(rule.evaluate(health: health, previous: lastHealth, context: ctx), now: health.generatedAt)
    }

    private func record(_ findings: [Finding], now: Timestamp) async -> [Alert] {
        var out: [Alert] = []
        for f in findings {
            stats.findings += 1
            if suppressions.contains(where: { $0.matches(f, now: now) }) { stats.suppressed += 1; continue }
            do {
                let (alert, isNew) = try await alerts.record(f, origin: origin)
                if isNew { stats.alertsCreated += 1 } else { stats.alertsUpdated += 1 }
                out.append(alert)
                onAlert?(alert, isNew)
            } catch { log.error("alert store failed: \(error.localizedDescription, privacy: .public)") }
        }
        return out
    }
}
