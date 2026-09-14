import CryptoKit
import Foundation
import NetSentryCore

/// What an export may reveal. Hashing is keyed with a per-export salt so hashes from different exports cannot
/// be joined, while identical addresses inside one export stay comparable.
public struct RedactionPolicy: Sendable, Codable, Hashable {
    public var hashInternalAddresses = false
    public var hashExternalAddresses = false
    public var dropMACs = true
    public var dropHostnames = false
    public var dropRawMessages = true
    public var dropNotes = false
    public var dropUsernames = false
    /// Random per export unless the caller wants reproducible hashes across files of one bundle.
    public var salt: String

    public init(hashInternalAddresses: Bool = false, hashExternalAddresses: Bool = false, dropMACs: Bool = true, dropHostnames: Bool = false,
                dropRawMessages: Bool = true, dropNotes: Bool = false, dropUsernames: Bool = false, salt: String = UUID().uuidString) {
        self.hashInternalAddresses = hashInternalAddresses; self.hashExternalAddresses = hashExternalAddresses; self.dropMACs = dropMACs
        self.dropHostnames = dropHostnames; self.dropRawMessages = dropRawMessages; self.dropNotes = dropNotes; self.dropUsernames = dropUsernames; self.salt = salt
    }

    /// Everything as stored (for the user's own archives).
    public static let none = RedactionPolicy(dropMACs: false, dropRawMessages: false)
    /// Suitable for sending to a third party: internal addresses hashed, MACs, hostnames, raw text and notes removed.
    public static let sharing = RedactionPolicy(hashInternalAddresses: true, dropMACs: true, dropHostnames: true, dropRawMessages: true, dropNotes: true, dropUsernames: true)

    public var summary: String {
        var parts: [String] = []
        if hashInternalAddresses { parts.append("internal addresses hashed") }
        if hashExternalAddresses { parts.append("external addresses hashed") }
        if dropMACs { parts.append("MACs removed") }
        if dropHostnames { parts.append("hostnames removed") }
        if dropRawMessages { parts.append("raw messages removed") }
        if dropNotes { parts.append("notes removed") }
        if dropUsernames { parts.append("usernames removed") }
        return parts.isEmpty ? "no redaction" : parts.joined(separator: ", ")
    }
}

public struct Redactor: Sendable {
    public let policy: RedactionPolicy
    public init(_ policy: RedactionPolicy) { self.policy = policy }

    public func address(_ ip: IPAddress, isInternal: Bool) -> String {
        let hash = isInternal ? policy.hashInternalAddresses : policy.hashExternalAddresses
        return hash ? Self.token("ip", ip.description, salt: policy.salt) : ip.description
    }
    public func address(_ ip: IPAddress?, isInternal: Bool) -> String { ip.map { address($0, isInternal: isInternal) } ?? "" }
    public func mac(_ mac: String?) -> String { policy.dropMACs ? (mac == nil ? "" : "[mac]") : (mac ?? "") }
    public func hostname(_ h: String?) -> String { policy.dropHostnames ? (h == nil ? "" : "[host]") : (h ?? "") }
    public func username(_ u: String?) -> String { policy.dropUsernames ? (u == nil ? "" : "[user]") : (u ?? "") }
    public func raw(_ r: String?) -> String { policy.dropRawMessages ? "" : (r ?? "") }
    public func note(_ n: String) -> String { policy.dropNotes ? "[note removed]" : n }

    /// Free text (messages, titles, explanations) with every address that the policy hashes replaced.
    public func text(_ s: String, isInternal: (IPAddress) -> Bool) -> String {
        guard policy.hashInternalAddresses || policy.hashExternalAddresses else { return s }
        var out = ""
        var i = s.startIndex
        while i < s.endIndex {
            let c = s[i]
            if c.isHexDigit || c == "." || c == ":" {
                var j = i
                while j < s.endIndex, s[j].isHexDigit || s[j] == "." || s[j] == ":" { j = s.index(after: j) }
                let token = String(s[i..<j])
                if token.contains(".") || token.filter({ $0 == ":" }).count >= 2, let ip = IPAddress(token) {
                    out += address(ip, isInternal: isInternal(ip))
                } else { out += token }
                i = j
            } else { out.append(c); i = s.index(after: i) }
        }
        return out
    }

    static func token(_ prefix: String, _ value: String, salt: String) -> String {
        let digest = SHA256.hash(data: Data((salt + "|" + value).utf8))
        return prefix + "-" + digest.prefix(6).map { String(format: "%02x", $0) }.joined()
    }
}

enum CSV {
    static func escape(_ s: String) -> String {
        if s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r") { return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
        return s
    }
    static func line(_ fields: [String]) -> String { fields.map(escape).joined(separator: ",") + "\n" }
}

enum ISO {
    /// ISO8601DateFormatter is documented as thread-safe; it is created once and never mutated afterwards.
    nonisolated(unsafe) static let formatter: ISO8601DateFormatter = { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return f }()
    static func string(_ t: Timestamp?) -> String { t.map { formatter.string(from: $0.date) } ?? "" }
}
