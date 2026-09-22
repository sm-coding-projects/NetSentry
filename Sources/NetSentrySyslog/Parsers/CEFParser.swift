import Foundation
import NetSentryCore

/// ArcSight CEF events (`CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value ...`). UniFi Network
/// forwards its own events in this format (threats, client connect/roam/disconnect, VPN, WAN health, admin
/// audit). The header goes into `cef.*` attributes and `ruleID` / `ruleName`; for UniFi lines the
/// `UNIFIcategory` picks the event family and the UNIFI* fields fill the typed columns.
public struct CEFParser: SyslogFamilyParser {
    public static let name = "cef"
    public static let version: UInt16 = 1
    /// `.unknown` here means "decided per line" (see `SyslogParser`).
    public static let family: EventType = .unknown
    public static let verified = true
    public static let description = "CEF events; UniFi Network categories (Security, Client Devices, VPN, WAN, Audit) mapped to families"

    public init() {}

    public func parse(_ e: inout SyslogEvent) -> Bool {
        let text: Substring
        if e.appName == "CEF" { text = Substring(e.message) }
        else if e.message.hasPrefix("CEF:") { text = e.message.dropFirst(4) }
        else { return false }

        // Header: 7 pipe-separated fields, `\|` and `\\` escaped.
        var fields: [String] = []
        var cur = ""
        var i = text.startIndex
        while i < text.endIndex, fields.count < 7 {
            let c = text[i]
            if c == "\\", let n = text.index(i, offsetBy: 1, limitedBy: text.endIndex), n < text.endIndex, text[n] == "|" || text[n] == "\\" {
                cur.append(text[n]); i = text.index(after: n); continue
            }
            if c == "|" { fields.append(cur); cur = ""; i = text.index(after: i); continue }
            cur.append(c); i = text.index(after: i)
        }
        guard fields.count == 7, Int(fields[0]) != nil else { return false }
        let ext = Self.parseExtension(text[i...])

        e.attributes["cef.vendor"] = fields[1]
        e.attributes["cef.product"] = fields[2]
        e.attributes["cef.product_version"] = fields[3]
        e.attributes["cef.signature"] = fields[4]
        e.attributes["cef.name"] = fields[5]
        e.attributes["cef.severity"] = fields[6]
        for (k, v) in ext { e.attributes["cef.\(k)"] = v }
        e.ruleID = fields[4]
        e.ruleName = fields[5]
        if e.appName == "CEF" { e.appName = fields[2] }

        e.srcIP = ext["src"].flatMap(IPAddress.init)
        e.dstIP = ext["dst"].flatMap(IPAddress.init)
        e.srcPort = ext["spt"].flatMap { UInt16($0) }
        e.dstPort = ext["dpt"].flatMap { UInt16($0) }
        if let p = ext["proto"] { e.protocolNumber = Self.protocolNumber(p) }
        switch ext["act"]?.lowercased() {
        case "allowed", "allow", "accept", "accepted": e.action = .allow
        case "blocked", "block", "drop", "dropped": e.action = .block
        case "denied", "deny", "reject", "rejected": e.action = .deny
        default: break
        }

        let isUniFi = fields[1].caseInsensitiveCompare("Ubiquiti") == .orderedSame || ext["UNIFIcategory"] != nil
        switch ext["UNIFIcategory"] {
        case "Security":
            e.eventType = .ids
            e.idsSignature = ext["UNIFIipsSignature"] ?? fields[5]
            e.idsSignatureID = ext["UNIFIipsSignatureId"].flatMap { Int64($0) }
            e.idsCategory = ext["UNIFIpolicyName"] ?? ext["UNIFIpolicyType"]
            // Stored as a Suricata-style priority (1 = most severe) so the IDS-correlated rule reads it unchanged.
            switch ext["UNIFIrisk"]?.lowercased() {
            case "high", "critical": e.idsSeverity = 1
            case "medium": e.idsSeverity = 2
            case "low": e.idsSeverity = 3
            default: e.idsSeverity = (UInt8(fields[6]) ?? 0) >= 7 ? 1 : ((UInt8(fields[6]) ?? 0) >= 4 ? 2 : 3)
            }
            e.deviceID = ext["UNIFIsrcClientMac"] ?? ext["UNIFIdeviceMac"]
            if e.srcIP == nil { e.srcIP = ext["UNIFIsrcClientIp"].flatMap(IPAddress.init) }
            if e.dstIP == nil { e.dstIP = ext["UNIFIdstClientIp"].flatMap(IPAddress.init) }
            if e.action == nil { e.action = .alert }
        case "Audit":
            e.eventType = .auth
            e.username = ext["UNIFIadmin"]
        case "Client Devices":
            e.eventType = .client
            e.deviceID = ext["UNIFIclientMac"]
            if e.srcIP == nil { e.srcIP = ext["UNIFIclientIp"].flatMap(IPAddress.init) }
        case "VPN":
            e.eventType = .vpn
            e.username = ext["suser"]
            if e.srcIP == nil { e.srcIP = ext["UNIFIclientIp"].flatMap(IPAddress.init) }
        case "Internet and WAN":
            e.eventType = .system
            e.deviceID = ext["UNIFIdeviceMac"]
        default:
            e.eventType = isUniFi ? .unifiOther : .system
        }
        if let msg = ext["msg"], !msg.isEmpty { e.message = msg }
        return true
    }

    /// `key=value key2=value with spaces ...` — a new pair starts at a token whose head is `key=`; `\=` and `\\` are unescaped.
    static func parseExtension(_ s: Substring) -> [String: String] {
        var out: [String: String] = [:]
        var key: String?
        var value = ""
        func flush() { if let k = key { out[k] = value.trimmingCharacters(in: .whitespaces) } }
        for tok in s.split(separator: " ", omittingEmptySubsequences: false) {
            if let eq = tok.firstIndex(of: "="), eq > tok.startIndex, tok[tok.startIndex..<eq].allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." }),
               tok[tok.index(before: eq)] != "\\" {
                flush()
                key = String(tok[tok.startIndex..<eq])
                value = unescape(tok[tok.index(after: eq)...])
            } else if key != nil {
                value += " " + unescape(tok)
            }
        }
        flush()
        return out
    }

    private static func unescape(_ t: Substring) -> String {
        guard t.contains("\\") else { return String(t) }
        return t.replacingOccurrences(of: "\\=", with: "=").replacingOccurrences(of: "\\\\", with: "\\")
            .replacingOccurrences(of: "\\n", with: "\n").replacingOccurrences(of: "\\r", with: "\r")
    }

    static func protocolNumber(_ p: String) -> UInt8? {
        switch p.uppercased() {
        case "TCP": 6
        case "UDP": 17
        case "ICMP": 1
        case "ICMPV6": 58
        case "GRE": 47
        case "ESP": 50
        default: UInt8(p)
        }
    }
}
