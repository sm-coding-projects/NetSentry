import Foundation
import NetSentryCore
import NetSentryDetection
import NetSentryEnrichment
import NetSentryIPC

/// Typed wrappers over the collector's generic security/entity XPC operation.
struct SecurityClient {
    let client: CollectorClient
    private static let dec: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .millisecondsSince1970; return d }()

    private func call<T: Decodable>(_ op: String, _ args: [String: String] = [:], as: T.Type) async throws -> T {
        let r = try await client.request(SecurityRequest(op: op, args: args), timeout: .seconds(30))
        return try Self.dec.decode(T.self, from: r.json)
    }

    func alerts(states: [AlertState]? = nil, severities: [AlertSeverity]? = nil, clientID: Int64? = nil) async throws -> [Alert] {
        var a: [String: String] = [:]
        if let s = states { a["states"] = s.map(\.rawValue).joined(separator: ",") }
        if let s = severities { a["severities"] = s.map { "\($0.rawValue)" }.joined(separator: ",") }
        if let c = clientID { a["clientID"] = "\(c)" }
        return try await call("alerts.list", a, as: [Alert].self)
    }
    func alert(id: Int64) async throws -> Alert? { try await call("alerts.get", ["id": "\(id)"], as: Alert?.self) }
    func counts() async throws -> [String: Int] { try await call("alerts.counts", as: [String: Int].self) }
    func setState(_ id: Int64, _ state: AlertState) async throws -> Alert? { try await call("alerts.setState", ["id": "\(id)", "state": state.rawValue], as: Alert?.self) }
    func addNote(_ id: Int64, _ text: String) async throws -> Alert? { try await call("alerts.addNote", ["id": "\(id)", "text": text], as: Alert?.self) }
    func suppressions() async throws -> [Suppression] { try await call("suppressions.list", as: [Suppression].self) }
    func addSuppression(_ args: [String: String]) async throws -> [Suppression] { try await call("suppressions.add", args, as: [Suppression].self) }
    func removeSuppression(_ id: Int64) async throws -> [Suppression] { try await call("suppressions.remove", ["id": "\(id)"], as: [Suppression].self) }
    func expectations() async throws -> [[String: String]] { try await call("expectations.list", as: [[String: String]].self) }
    func addExpectation(scopeType: String, scopeValue: String, kind: String, value: String, note: String? = nil) async throws {
        _ = try await call("expectations.add", ["scopeType": scopeType, "scopeValue": scopeValue, "kind": kind, "value": value, "note": note ?? ""], as: [String: Bool].self)
    }
    func removeExpectation(_ id: Int64) async throws { _ = try await call("expectations.remove", ["id": "\(id)"], as: [String: Bool].self) }
    func rules() async throws -> [[String: String]] { try await call("rules.list", as: [[String: String]].self) }
    func setRule(_ name: String, enabled: Bool?, params: [String: Double]) async throws {
        var a = ["name": name]; if let e = enabled { a["enabled"] = "\(e)" }; for (k, v) in params { a["param.\(k)"] = "\(v)" }
        _ = try await call("rules.set", a, as: [String: Bool].self)
    }
    func clients() async throws -> [ClientIdentity] { try await call("clients.list", as: [ClientIdentity].self) }
    func client(id: Int64) async throws -> ClientIdentity? { try await call("clients.get", ["id": "\(id)"], as: ClientIdentity?.self) }
    func rename(_ id: Int64, _ name: String) async throws -> ClientIdentity? { try await call("clients.rename", ["id": "\(id)", "name": name], as: ClientIdentity?.self) }
    func setNotes(_ id: Int64, _ notes: String) async throws -> ClientIdentity? { try await call("clients.setNotes", ["id": "\(id)", "notes": notes], as: ClientIdentity?.self) }
    func setTags(_ id: Int64, _ tags: [String]) async throws -> ClientIdentity? { try await call("clients.setTags", ["id": "\(id)", "tags": tags.joined(separator: ",")], as: ClientIdentity?.self) }
    func setTrusted(_ id: Int64, _ trusted: Bool) async throws -> ClientIdentity? { try await call("clients.setTrusted", ["id": "\(id)", "trusted": "\(trusted)"], as: ClientIdentity?.self) }
    func merge(_ id: Int64, into: Int64) async throws -> ClientIdentity? { try await call("clients.merge", ["id": "\(id)", "into": "\(into)"], as: ClientIdentity?.self) }
    func split(_ id: Int64, ip: String) async throws -> ClientIdentity? { try await call("clients.split", ["id": "\(id)", "ip": ip], as: ClientIdentity?.self) }
    func detectionStats() async throws -> DetectionEngine.Stats { try await call("detection.stats", as: DetectionEngine.Stats.self) }
}
