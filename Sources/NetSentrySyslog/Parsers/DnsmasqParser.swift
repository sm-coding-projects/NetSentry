import Foundation
import NetSentryCore

/// dnsmasq DHCP lease lines (`DHCPACK(br0) 192.168.1.20 aa:bb:cc:dd:ee:ff hostname`), the DHCP server used
/// by UniFi gateways. Public dnsmasq format; the UCG Fiber emits it unchanged behind its repeated-hostname
/// wrapper (verified from captures, see the fixture).
public struct DnsmasqDHCPParser: SyslogFamilyParser {
    public static let name = "dnsmasq-dhcp"
    public static let version: UInt16 = 1
    public static let family: EventType = .dhcp
    public static let verified = true
    public static let description = "dnsmasq DHCPDISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE lines"

    public init() {}

    public func parse(_ e: inout SyslogEvent) -> Bool {
        let msg = e.message
        guard let r = msg.range(of: #"DHCP(ACK|REQUEST|DISCOVER|OFFER|NAK|RELEASE|INFORM|DECLINE)\("#, options: .regularExpression) else { return false }
        let kind = String(msg[msg.index(r.lowerBound, offsetBy: 4)..<msg.index(before: r.upperBound)])
        var rest = msg[r.upperBound...]
        guard let close = rest.firstIndex(of: ")") else { return false }
        let iface = String(rest[rest.startIndex..<close])
        rest = rest[rest.index(after: close)...]
        let parts = rest.split(separator: " ", omittingEmptySubsequences: true)
        e.attributes["dhcp.message"] = kind
        e.inInterface = iface
        var idx = 0
        if idx < parts.count, let ip = IPAddress(String(parts[idx])) { e.srcIP = ip; idx += 1 }
        if idx < parts.count, let mac = MACAddress(String(parts[idx])) { e.deviceID = mac.description; idx += 1 }
        if idx < parts.count { e.attributes["dhcp.hostname"] = String(parts[idx]) }
        return true
    }
}

/// dnsmasq DNS query logging (`query[A] example.com from 192.168.1.20`).
public struct DnsmasqDNSParser: SyslogFamilyParser {
    public static let name = "dnsmasq-dns"
    public static let version: UInt16 = 1
    public static let family: EventType = .dns
    public static let verified = false
    public static let description = "dnsmasq query/reply/forwarded lines when DNS logging is enabled"

    public init() {}

    public func parse(_ e: inout SyslogEvent) -> Bool {
        let msg = e.message
        guard msg.hasPrefix("query[") || msg.hasPrefix("forwarded ") || msg.hasPrefix("reply ") || msg.hasPrefix("cached ") else { return false }
        if msg.hasPrefix("query[") {
            let parts = msg.split(separator: " ")
            guard parts.count >= 4, let br = parts[0].firstIndex(of: "]") else { return false }
            e.attributes["dns.type"] = String(parts[0][parts[0].index(parts[0].startIndex, offsetBy: 6)..<br])
            e.attributes["dns.name"] = String(parts[1])
            if parts[2] == "from", let ip = IPAddress(String(parts[3])) { e.srcIP = ip }
        } else {
            let parts = msg.split(separator: " ")
            if parts.count >= 2 { e.attributes["dns.name"] = String(parts[1]) }
            if parts.count >= 4, let ip = IPAddress(String(parts[3])) { e.dstIP = ip }
            e.attributes["dns.op"] = String(parts[0])
        }
        return true
    }
}
