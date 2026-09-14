import Foundation
import NetSentryCore

/// Linux netfilter `LOG` target lines (`IN=… OUT=… SRC=… DST=… PROTO=… SPT=… DPT=…`), which UniFi gateways
/// emit for firewall rules with logging enabled, prefixed by a bracketed rule label such as
/// `[WAN_LOCAL-D-4001]`. The key=value grammar is the public kernel format; the prefix grammar is
/// interpreted loosely (label kept verbatim, action guessed from a `-A-`/`-D-`/`-R-` token) until
/// confirmed by a real UCG Fiber fixture.
public struct NetfilterParser: SyslogFamilyParser {
    public static let name = "netfilter-log"
    public static let version: UInt16 = 1
    public static let family: EventType = .firewall
    public static let verified = false
    public static let description = "Linux netfilter LOG key=value firewall lines with a UniFi rule prefix"

    public init() {}

    public func parse(_ e: inout SyslogEvent) -> Bool {
        let msg = e.message
        guard msg.contains("SRC="), msg.contains("DST="), msg.contains("IN=") || msg.contains("OUT=") else { return false }
        var rest = Substring(msg)
        if let inRange = rest.range(of: "IN=") {
            let prefix = rest[rest.startIndex..<inRange.lowerBound].trimmingCharacters(in: .whitespaces)
            if !prefix.isEmpty {
                let label = prefix.trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
                e.ruleName = label
                e.attributes["fw.prefix"] = prefix
                let upper = label.uppercased()
                let tokens = upper.split(whereSeparator: { $0 == "-" || $0 == " " || $0 == "_" })
                if tokens.contains("D") || upper.contains("DROP") || tokens.contains("DENY") { e.action = .deny }
                else if tokens.contains("R") || upper.contains("REJECT") { e.action = .reject }
                else if tokens.contains("A") || upper.contains("ACCEPT") || upper.contains("ALLOW") { e.action = .allow }
                if let idTok = tokens.last, idTok.allSatisfy(\.isNumber) { e.ruleID = String(idTok) }
            }
            rest = rest[inRange.lowerBound...]
        }
        var kv: [String: String] = [:]
        var flags: [String] = []
        for tok in rest.split(separator: " ") {
            if let eq = tok.firstIndex(of: "=") {
                kv[String(tok[tok.startIndex..<eq])] = String(tok[tok.index(after: eq)...])
            } else if !tok.isEmpty {
                flags.append(String(tok))
            }
        }
        e.srcIP = kv["SRC"].flatMap(IPAddress.init)
        e.dstIP = kv["DST"].flatMap(IPAddress.init)
        e.srcPort = kv["SPT"].flatMap { UInt16($0) }
        e.dstPort = kv["DPT"].flatMap { UInt16($0) }
        if let p = kv["PROTO"] {
            switch p.uppercased() {
            case "TCP": e.protocolNumber = 6
            case "UDP": e.protocolNumber = 17
            case "ICMP": e.protocolNumber = 1
            case "ICMPV6": e.protocolNumber = 58
            case "IGMP": e.protocolNumber = 2
            case "GRE": e.protocolNumber = 47
            case "ESP": e.protocolNumber = 50
            default: e.protocolNumber = UInt8(p)
            }
        }
        e.inInterface = kv["IN"].flatMap { $0.isEmpty ? nil : $0 }
        e.outInterface = kv["OUT"].flatMap { $0.isEmpty ? nil : $0 }
        if let mac = kv["MAC"], mac.count >= 41 {
            let parts = mac.split(separator: ":")
            if parts.count >= 14 { e.deviceID = parts[6..<12].joined(separator: ":") }   // dst(6):src(6):ethertype(2)
        }
        for (k, v) in kv where !["SRC", "DST", "SPT", "DPT", "PROTO", "IN", "OUT"].contains(k) { e.attributes["fw.\(k.lowercased())"] = v }
        if !flags.isEmpty { e.attributes["fw.flags"] = flags.joined(separator: " ") }
        if e.action == nil { e.action = .unknown }
        return true
    }
}
