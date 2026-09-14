import Foundation
import NetSentryCore

/// Suricata "fast" alert format, which UniFi's IDS/IPS (Suricata-based) is expected to forward:
/// `[1:2001219:20] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 1.2.3.4:5678 -> 5.6.7.8:22`
public struct SuricataFastParser: SyslogFamilyParser {
    public static let name = "suricata-fast"
    public static let version: UInt16 = 1
    public static let family: EventType = .ids
    public static let verified = false
    public static let description = "Suricata fast.log style IDS/IPS alerts"

    public init() {}

    public func parse(_ e: inout SyslogEvent) -> Bool {
        let msg = e.message
        guard let sig = msg.range(of: #"\[(\d+):(\d+):(\d+)\]"#, options: .regularExpression),
              msg.contains("Classification:") || msg.contains("Priority:") else { return false }
        let ids = msg[sig].trimmingCharacters(in: CharacterSet(charactersIn: "[]")).split(separator: ":")
        if ids.count == 3 { e.idsSignatureID = Int64(ids[1]); e.attributes["ids.gid"] = String(ids[0]); e.attributes["ids.rev"] = String(ids[2]) }
        var after = msg[sig.upperBound...]
        if let sep = after.range(of: "[**]") {
            e.idsSignature = after[after.startIndex..<sep.lowerBound].trimmingCharacters(in: .whitespaces)
            after = after[sep.upperBound...]
        } else if let br = after.firstIndex(of: "[") {
            e.idsSignature = after[after.startIndex..<br].trimmingCharacters(in: .whitespaces)
        }
        if let r = msg.range(of: #"\[Classification: ([^\]]+)\]"#, options: .regularExpression) {
            e.idsCategory = String(msg[r].dropFirst(17).dropLast())
        }
        if let r = msg.range(of: #"\[Priority: (\d+)\]"#, options: .regularExpression) {
            e.idsSeverity = UInt8(msg[r].dropFirst(11).dropLast())
        }
        if let r = msg.range(of: #"\{(\w+)\} (\S+):(\d+) -> (\S+):(\d+)"#, options: .regularExpression) {
            let seg = msg[r]
            let close = seg.firstIndex(of: "}")!
            let proto = seg[seg.index(after: seg.startIndex)..<close]
            e.protocolNumber = proto == "TCP" ? 6 : proto == "UDP" ? 17 : proto == "ICMP" ? 1 : nil
            let ends = seg[close...].dropFirst(2).components(separatedBy: " -> ")
            if ends.count == 2 {
                if let (ip, port) = Self.split(ends[0]) { e.srcIP = ip; e.srcPort = port }
                if let (ip, port) = Self.split(ends[1]) { e.dstIP = ip; e.dstPort = port }
            }
        } else if let r = msg.range(of: #"\{(\w+)\} (\S+) -> (\S+)"#, options: .regularExpression) {
            let parts = msg[r].split(separator: " ")
            if parts.count == 4 {
                let proto = parts[0].dropFirst().dropLast()
                e.protocolNumber = proto == "TCP" ? 6 : proto == "UDP" ? 17 : proto == "ICMP" ? 1 : nil
                e.srcIP = IPAddress(String(parts[1])); e.dstIP = IPAddress(String(parts[3]))
            }
        }
        if msg.contains("[Drop]") || msg.lowercased().contains("blocked") { e.action = .block } else { e.action = .alert }
        return true
    }

    private static func split(_ hostPort: String) -> (IPAddress, UInt16)? {
        guard let colon = hostPort.lastIndex(of: ":"), let port = UInt16(hostPort[hostPort.index(after: colon)...]) else { return nil }
        let host = hostPort[hostPort.startIndex..<colon].trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard let ip = IPAddress(host) else { return nil }
        return (ip, port)
    }
}
