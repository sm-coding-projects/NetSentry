import Foundation

/// Normalized syslog event. The original message is always preserved in `raw`.
public struct SyslogEvent: Hashable, Sendable, Codable, Identifiable {
    public static let schemaVersion: UInt16 = 1

    public var id: Int64 = 0
    public var origin: Origin = .live
    public var receivedAt: Timestamp
    public var eventTime: Timestamp?
    public var timeInferred = false
    public var sourceIP: IPAddress
    public var transport: Transport
    public var syslogVersion: UInt8 = 0     // 0 = RFC 3164 style, 1 = RFC 5424
    public var facility: SyslogFacility = .user
    public var severity: SyslogSeverity = .informational
    public var priorityPresent = true
    public var hostname: String?
    public var appName: String?
    public var procID: String?
    public var msgID: String?
    public var structuredData: [String: [String: String]] = [:]
    public var message: String
    public var raw: String?
    public var rawBytes: Data?
    public var parserName: String = "fallback"
    public var parserVersion: UInt16 = 0
    public var parseStatus: ParseStatus = .unparsed
    public var eventType: EventType = .unknown

    public var srcIP: IPAddress?
    public var dstIP: IPAddress?
    public var srcPort: UInt16?
    public var dstPort: UInt16?
    public var protocolNumber: UInt8?
    public var action: FirewallAction?
    public var inInterface: String?
    public var outInterface: String?
    public var vlan: UInt16?
    public var ruleID: String?
    public var ruleName: String?
    public var username: String?
    public var deviceID: String?
    public var idsSignatureID: Int64?
    public var idsSignature: String?
    public var idsCategory: String?
    public var idsSeverity: UInt8?
    public var attributes: [String: String] = [:]
    public var enrichment = FlowEnrichment()

    public init(receivedAt: Timestamp, sourceIP: IPAddress, transport: Transport, message: String, raw: String?) {
        self.receivedAt = receivedAt
        self.sourceIP = sourceIP
        self.transport = transport
        self.message = message
        self.raw = raw
    }

    public var effectiveTime: Timestamp { eventTime ?? receivedAt }
}
