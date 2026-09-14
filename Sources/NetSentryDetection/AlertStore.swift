import Foundation
import NetSentryCore
import NetSentryPersistence

/// A stored alert with its workflow state.
public struct Alert: Sendable, Hashable, Codable, Identifiable {
    public var id: Int64
    public var ruleName: String
    public var ruleVersion: Int
    public var severity: AlertSeverity
    public var state: AlertState
    public var title: String
    public var summary: String
    public var explanation: String
    public var createdAt: Timestamp
    public var updatedAt: Timestamp
    public var firstOccurrence: Timestamp
    public var lastOccurrence: Timestamp
    public var occurrenceCount: Int
    public var dedupeKey: String
    public var clientID: Int64?
    public var entity: Finding.Entity
    public var evidence: [String: String]
    public var baseline: Finding.Baseline?
    public var flowIDs: [Int64]
    public var eventIDs: [Int64]
    public var steps: [String]
    public var resolvedAt: Timestamp?
    public var origin: Origin
    public var notes: [AlertNote]
}

public struct AlertNote: Sendable, Hashable, Codable, Identifiable {
    public var id: Int64
    public var createdAt: Timestamp
    public var text: String
}

/// A user exception: findings matching the scope are suppressed before they become alerts.
public struct Suppression: Sendable, Hashable, Codable, Identifiable {
    public var id: Int64
    public var ruleName: String          // "*" = any rule
    public var clientID: Int64?
    public var vlan: String?
    public var destination: String?      // ip
    public var port: Int?
    public var asn: Int?
    public var country: String?
    public var startHour: Int?           // local hour-of-day window
    public var endHour: Int?
    public var expiresAt: Timestamp?
    public var reason: String?
    public var createdAt: Timestamp

    public init(id: Int64 = 0, ruleName: String = "*", clientID: Int64? = nil, vlan: String? = nil, destination: String? = nil, port: Int? = nil, asn: Int? = nil,
                country: String? = nil, startHour: Int? = nil, endHour: Int? = nil, expiresAt: Timestamp? = nil, reason: String? = nil, createdAt: Timestamp = .now) {
        self.id = id; self.ruleName = ruleName; self.clientID = clientID; self.vlan = vlan; self.destination = destination; self.port = port; self.asn = asn
        self.country = country; self.startHour = startHour; self.endHour = endHour; self.expiresAt = expiresAt; self.reason = reason; self.createdAt = createdAt
    }

    public func matches(_ f: Finding, now: Timestamp) -> Bool {
        if let e = expiresAt, e < now { return false }
        if ruleName != "*", ruleName != f.ruleName { return false }
        if let c = clientID, f.clientID != c { return false }
        if let d = destination, f.evidence["destination"] != d, f.entity.id != d, f.evidence["resolver"] != d { return false }
        if let p = port, f.evidence["port"] != "\(p)" { return false }
        if let a = asn, f.evidence["asn"] != "\(a)", !(f.entity.kind == "asn" && f.entity.id == "\(a)") { return false }
        if let c = country, f.evidence["country"] != c, !(f.entity.kind == "country" && f.entity.id == c) { return false }
        if let v = vlan, f.evidence["src_network"] != v, f.evidence["dst_network"] != v { return false }
        if let s = startHour, let e = endHour {
            var cal = Calendar(identifier: .gregorian); cal.timeZone = .current
            let h = cal.component(.hour, from: f.occurredAt.date)
            let inWindow = s <= e ? (h >= s && h < e) : (h >= s || h < e)
            if !inWindow { return false }
        }
        return true
    }
}

/// SQLite-backed alert workflow. All mutations are transactional; alerts are never deleted by retention.
public actor AlertStore {
    private let meta: MetaStore
    public init(meta: MetaStore) { self.meta = meta }

    private static let enc = JSONEncoder()
    private static let dec = JSONDecoder()
    private static func json<T: Encodable>(_ v: T) -> String { String(decoding: (try? enc.encode(v)) ?? Data("null".utf8), as: UTF8.self) }
    private static func parse<T: Decodable>(_ s: String?, _ t: T.Type) -> T? { s.flatMap { try? dec.decode(t, from: Data($0.utf8)) } }

    /// Creates a new alert or increments the open/acknowledged alert with the same dedupe key.
    /// Returns (alert, isNew).
    public func record(_ f: Finding, origin: Origin) throws -> (Alert, Bool) {
        if let existing = try meta.db.query("SELECT id, state FROM alerts WHERE dedupe_key = ? AND state IN ('open','acknowledged') ORDER BY id DESC LIMIT 1", [f.dedupeKey]).first,
           let id = existing.int64("id") {
            try meta.db.run("UPDATE alerts SET occurrence_count = occurrence_count + 1, last_occurrence = ?, updated_at = ?, evidence_json = ?, refs_json = ? WHERE id = ?",
                            [f.occurredAt, Timestamp.now, Self.json(f.evidence), Self.json(["flows": f.flowIDs, "events": f.eventIDs]), id])
            return (try alert(id: id)!, false)
        }
        try meta.db.run("""
            INSERT INTO alerts (rule_name, rule_version, severity, state, title, summary, explanation_md, created_at, updated_at, first_occurrence, last_occurrence,
              occurrence_count, dedupe_key, client_id, entity_json, evidence_json, baseline_json, refs_json, steps_json, origin)
            VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [f.ruleName, f.ruleVersion, Int(f.severity.rawValue), f.title, f.summary, f.explanation, Timestamp.now, Timestamp.now, f.occurredAt, f.occurredAt,
                  f.dedupeKey, f.clientID, Self.json(f.entity), Self.json(f.evidence), f.baseline.map { Self.json($0) }, Self.json(["flows": f.flowIDs, "events": f.eventIDs]),
                  Self.json(f.steps), Int(origin.rawValue)])
        return (try alert(id: meta.db.lastInsertRowID)!, true)
    }

    public func alert(id: Int64) throws -> Alert? { try alerts(whereSQL: "id = ?", params: [id]).first }

    public func alerts(states: [AlertState]? = nil, severities: [AlertSeverity]? = nil, clientID: Int64? = nil, limit: Int = 500) throws -> [Alert] {
        var w: [String] = ["1=1"]; var p: [any SQLBindable] = []
        if let s = states, !s.isEmpty { w.append("state IN (\(s.map { _ in "?" }.joined(separator: ",")))"); p += s.map(\.rawValue) }
        if let s = severities, !s.isEmpty { w.append("severity IN (\(s.map { _ in "?" }.joined(separator: ",")))"); p += s.map { Int($0.rawValue) } }
        if let c = clientID { w.append("client_id = ?"); p.append(c) }
        return try alerts(whereSQL: w.joined(separator: " AND ") + " ORDER BY last_occurrence DESC LIMIT \(max(1, min(limit, 5_000)))", params: p)
    }

    private func alerts(whereSQL: String, params: [any SQLBindable]) throws -> [Alert] {
        try meta.db.query("SELECT * FROM alerts WHERE \(whereSQL)", params).map { r in
            let refs = Self.parse(r.string("refs_json"), [String: [Int64]].self) ?? [:]
            let notes = (try? meta.db.query("SELECT id, created_at, text FROM alert_notes WHERE alert_id = ? ORDER BY id", [r.int64("id") ?? 0]))?.map {
                AlertNote(id: $0.int64("id") ?? 0, createdAt: $0.timestamp("created_at") ?? .now, text: $0.string("text") ?? "") } ?? []
            return Alert(id: r.int64("id") ?? 0, ruleName: r.string("rule_name") ?? "", ruleVersion: r.int("rule_version") ?? 0,
                         severity: AlertSeverity(rawValue: UInt8(r.int("severity") ?? 0)) ?? .info, state: AlertState(rawValue: r.string("state") ?? "open") ?? .open,
                         title: r.string("title") ?? "", summary: r.string("summary") ?? "", explanation: r.string("explanation_md") ?? "",
                         createdAt: r.timestamp("created_at") ?? .now, updatedAt: r.timestamp("updated_at") ?? .now, firstOccurrence: r.timestamp("first_occurrence") ?? .now,
                         lastOccurrence: r.timestamp("last_occurrence") ?? .now, occurrenceCount: r.int("occurrence_count") ?? 1, dedupeKey: r.string("dedupe_key") ?? "",
                         clientID: r.int64("client_id"), entity: Self.parse(r.string("entity_json"), Finding.Entity.self) ?? .init(kind: "unknown", id: "", label: ""),
                         evidence: Self.parse(r.string("evidence_json"), [String: String].self) ?? [:], baseline: Self.parse(r.string("baseline_json"), Finding.Baseline.self),
                         flowIDs: refs["flows"] ?? [], eventIDs: refs["events"] ?? [], steps: Self.parse(r.string("steps_json"), [String].self) ?? [],
                         resolvedAt: r.timestamp("resolved_at"), origin: Origin(rawValue: UInt8(r.int("origin") ?? 0)) ?? .live, notes: notes)
        }
    }

    public func setState(_ id: Int64, _ state: AlertState) throws {
        try meta.db.run("UPDATE alerts SET state = ?, updated_at = ?, resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE NULL END WHERE id = ?", [state.rawValue, Timestamp.now, state.rawValue, Timestamp.now, id])
    }

    public func addNote(_ id: Int64, _ text: String) throws {
        try meta.db.run("INSERT INTO alert_notes (alert_id, created_at, text) VALUES (?, ?, ?)", [id, Timestamp.now, text])
        try meta.db.run("UPDATE alerts SET updated_at = ? WHERE id = ?", [Timestamp.now, id])
    }

    public func counts() throws -> [AlertState: Int] {
        var out: [AlertState: Int] = [:]
        for r in try meta.db.query("SELECT state, COUNT(*) AS n FROM alerts GROUP BY state") { if let s = AlertState(rawValue: r.string("state") ?? "") { out[s] = r.int("n") ?? 0 } }
        return out
    }

    // MARK: Suppressions and expectations

    public func suppressions() throws -> [Suppression] {
        try meta.db.query("SELECT id, rule_name, scope_json, expires_at, reason, created_at FROM suppressions ORDER BY id DESC").compactMap { r in
            guard var s = Self.parse(r.string("scope_json"), Suppression.self) else { return nil }
            s.id = r.int64("id") ?? 0; s.ruleName = r.string("rule_name") ?? "*"; s.expiresAt = r.timestamp("expires_at"); s.reason = r.string("reason"); s.createdAt = r.timestamp("created_at") ?? .now
            return s
        }
    }

    @discardableResult
    public func addSuppression(_ s: Suppression) throws -> Int64 {
        try meta.db.run("INSERT INTO suppressions (rule_name, scope_json, expires_at, reason, created_at) VALUES (?, ?, ?, ?, ?)", [s.ruleName, Self.json(s), s.expiresAt, s.reason, Timestamp.now])
        return meta.db.lastInsertRowID
    }

    public func removeSuppression(_ id: Int64) throws { try meta.db.run("DELETE FROM suppressions WHERE id = ?", [id]) }

    /// Expectations: (scope, kind, value) tuples the first-seen and VLAN rules consult, e.g. ("client","12","country","DE").
    public func addExpectation(scopeType: String, scopeValue: String, kind: String, value: String, note: String?) throws {
        try meta.db.run("INSERT OR IGNORE INTO expectations (scope_type, scope_value, kind, value, note, created_at) VALUES (?, ?, ?, ?, ?, ?)", [scopeType, scopeValue, kind, value, note, Timestamp.now])
    }
    public func removeExpectation(id: Int64) throws { try meta.db.run("DELETE FROM expectations WHERE id = ?", [id]) }
    public func expectations() throws -> [(id: Int64, scopeType: String, scopeValue: String, kind: String, value: String, note: String?)] {
        try meta.db.query("SELECT * FROM expectations ORDER BY scope_type, scope_value, kind, value").map {
            ($0.int64("id") ?? 0, $0.string("scope_type") ?? "", $0.string("scope_value") ?? "", $0.string("kind") ?? "", $0.string("value") ?? "", $0.string("note"))
        }
    }
    public func expectationSet() throws -> Set<String> { Set(try expectations().map { "\($0.scopeType)|\($0.scopeValue)|\($0.kind)|\($0.value)" }) }

    // MARK: Rule configuration

    public func ruleConfigurations() throws -> [String: RuleConfiguration] {
        var out: [String: RuleConfiguration] = [:]
        for r in try meta.db.query("SELECT name, enabled, params_json FROM rules") {
            var c = RuleConfiguration(); c.enabled = r.bool("enabled"); c.parameters = Self.parse(r.string("params_json"), [String: Double].self) ?? [:]
            out[r.string("name") ?? ""] = c
        }
        return out
    }
    public func setRuleConfiguration(_ name: String, version: Int, _ c: RuleConfiguration) throws {
        try meta.db.run("INSERT INTO rules (name, version, enabled, params_json, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET enabled = excluded.enabled, params_json = excluded.params_json, version = excluded.version, updated_at = excluded.updated_at",
                        [name, version, c.enabled, Self.json(c.parameters), Timestamp.now])
    }
}

/// SQLite implementation of the rule state store.
public struct SQLiteRuleState: RuleStateStore {
    private let db: SQLiteDatabase
    public init(meta: MetaStore) { db = meta.db }

    public func get(rule: String, key: String) throws -> String? { try db.scalar("SELECT json FROM rule_state WHERE rule_name = ? AND key = ?", [rule, key]).string }
    public func set(rule: String, key: String, value: String) throws {
        try db.run("INSERT INTO rule_state (rule_name, key, json, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(rule_name, key) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at", [rule, key, value, Timestamp.now])
    }
    public func firstSeen(scopeType: String, scopeValue: String, kind: String, key: String, at: Timestamp) throws -> Bool {
        let changed = try db.run("UPDATE first_seen SET last_seen = ?, count = count + 1 WHERE scope_type = ? AND scope_value = ? AND kind = ? AND key = ?", [at, scopeType, scopeValue, kind, key])
        if changed > 0 { return false }
        try db.run("INSERT OR IGNORE INTO first_seen (scope_type, scope_value, kind, key, first_seen, last_seen, count) VALUES (?, ?, ?, ?, ?, ?, 1)", [scopeType, scopeValue, kind, key, at, at])
        return true
    }
    public func hourlyOutboundBytes(clientID: Int64, hours: Int, before: Timestamp) throws -> [Int64] {
        let from = Timestamp(microseconds: before.microseconds - Int64(hours) * 3_600_000_000)
        return try db.query("SELECT (bucket / 3600000000) AS h, SUM(bytes) AS b FROM rollup_minute WHERE client_id = ? AND direction = 1 AND bucket >= ? AND bucket < ? GROUP BY h ORDER BY h", [clientID, from, before]).map { $0.int64("b") ?? 0 }
    }
    public func hourOfDayHistogram(clientID: Int64, days: Int, before: Timestamp) throws -> [Int64] {
        let from = Timestamp(microseconds: before.microseconds - Int64(days) * 86_400_000_000)
        var out = [Int64](repeating: 0, count: 24)
        var cal = Calendar(identifier: .gregorian); cal.timeZone = .current
        for r in try db.query("SELECT bucket, flows FROM rollup_minute WHERE client_id = ? AND direction = 1 AND bucket >= ? AND bucket < ?", [clientID, from, before]) {
            let h = cal.component(.hour, from: Timestamp(microseconds: r.int64("bucket") ?? 0).date)
            out[h] += r.int64("flows") ?? 0
        }
        return out
    }
}
