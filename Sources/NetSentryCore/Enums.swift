import Foundation

/// Where a record came from. Simulated data additionally lives in its own workspace.
public enum Origin: UInt8, Codable, Sendable, CaseIterable { case live = 0, simulated = 1, imported = 2 }

/// Derived direction relative to the monitored network.
public enum TrafficDirection: UInt8, Codable, Sendable, CaseIterable {
    case unknown = 0, outbound = 1, inbound = 2, lan = 3, transit = 4
    public var label: String {
        switch self {
        case .unknown: "Unknown"
        case .outbound: "Outbound"
        case .inbound: "Inbound"
        case .lan: "Internal"
        case .transit: "Transit"
        }
    }
}

public enum IPProtocol: UInt8, Sendable {
    case icmp = 1, igmp = 2, tcp = 6, udp = 17, gre = 47, esp = 50, ah = 51, icmpv6 = 58, sctp = 132
    public static func name(_ raw: UInt8) -> String {
        switch IPProtocol(rawValue: raw) {
        case .icmp: "ICMP"
        case .igmp: "IGMP"
        case .tcp: "TCP"
        case .udp: "UDP"
        case .gre: "GRE"
        case .esp: "ESP"
        case .ah: "AH"
        case .icmpv6: "ICMPv6"
        case .sctp: "SCTP"
        case nil: "proto \(raw)"
        }
    }
}

public enum FirewallAction: UInt8, Codable, Sendable, CaseIterable {
    case unknown = 0, allow = 1, deny = 2, reject = 3, block = 4, alert = 5
    public var label: String {
        switch self {
        case .unknown: "Unknown"
        case .allow: "Allowed"
        case .deny: "Denied"
        case .reject: "Rejected"
        case .block: "Blocked"
        case .alert: "Alert"
        }
    }
}

public enum EventType: UInt8, Codable, Sendable, CaseIterable {
    case unknown = 0, firewall = 1, ids = 2, auth = 3, vpn = 4, dhcp = 5, dns = 6, system = 7, client = 8, unifiOther = 9
    public var label: String {
        switch self {
        case .unknown: "Unknown"
        case .firewall: "Firewall"
        case .ids: "IDS/IPS"
        case .auth: "Authentication"
        case .vpn: "VPN"
        case .dhcp: "DHCP"
        case .dns: "DNS"
        case .system: "System"
        case .client: "Client"
        case .unifiOther: "UniFi"
        }
    }
}

public enum ParseStatus: UInt8, Codable, Sendable { case parsed = 0, partial = 1, unparsed = 2 }

public enum SyslogSeverity: UInt8, Codable, Sendable, CaseIterable, Comparable {
    case emergency = 0, alert, critical, error, warning, notice, informational, debug
    public var label: String {
        switch self {
        case .emergency: "Emergency"
        case .alert: "Alert"
        case .critical: "Critical"
        case .error: "Error"
        case .warning: "Warning"
        case .notice: "Notice"
        case .informational: "Info"
        case .debug: "Debug"
        }
    }
    public static func < (l: Self, r: Self) -> Bool { l.rawValue < r.rawValue }
}

public enum SyslogFacility: UInt8, Codable, Sendable {
    case kern = 0, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, ntp, audit, alert, clock,
         local0, local1, local2, local3, local4, local5, local6, local7
    public var label: String {
        switch self {
        case .kern: "kern"; case .user: "user"; case .mail: "mail"; case .daemon: "daemon"; case .auth: "auth"
        case .syslog: "syslog"; case .lpr: "lpr"; case .news: "news"; case .uucp: "uucp"; case .cron: "cron"
        case .authpriv: "authpriv"; case .ftp: "ftp"; case .ntp: "ntp"; case .audit: "audit"; case .alert: "alert"
        case .clock: "clock"; case .local0: "local0"; case .local1: "local1"; case .local2: "local2"; case .local3: "local3"
        case .local4: "local4"; case .local5: "local5"; case .local6: "local6"; case .local7: "local7"
        }
    }
}

public enum Transport: UInt8, Codable, Sendable, CaseIterable {
    case udp = 0, tcp = 1
    public var label: String { self == .udp ? "UDP" : "TCP" }
}

public enum ListenerKind: String, Codable, Sendable, CaseIterable {
    case ipfix, syslog
    public var label: String { self == .ipfix ? "IPFIX" : "Syslog" }
}

public enum AlertSeverity: UInt8, Codable, Sendable, CaseIterable, Comparable {
    case info = 0, low = 1, medium = 2, high = 3, critical = 4
    public var label: String {
        switch self {
        case .info: "Info"; case .low: "Low"; case .medium: "Medium"; case .high: "High"; case .critical: "Critical"
        }
    }
    public static func < (l: Self, r: Self) -> Bool { l.rawValue < r.rawValue }
}

public enum AlertState: String, Codable, Sendable, CaseIterable { case open, acknowledged, suppressed, resolved }
