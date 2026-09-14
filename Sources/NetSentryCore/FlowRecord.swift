import Foundation

/// Identifies an IPFIX exporter session as (transport source address, observation domain).
public struct ExporterKey: Hashable, Sendable, Codable, CustomStringConvertible {
    public let address: IPAddress
    public let observationDomain: UInt32
    public init(address: IPAddress, observationDomain: UInt32) {
        self.address = address
        self.observationDomain = observationDomain
    }
    public var description: String { "\(address)/\(observationDomain)" }
}

/// An unknown or enterprise-specific information element preserved verbatim.
public struct RawInformationElement: Hashable, Sendable, Codable {
    public let enterpriseNumber: UInt32   // 0 for IANA
    public let elementID: UInt16
    public let value: Data
    public init(enterpriseNumber: UInt32, elementID: UInt16, value: Data) {
        self.enterpriseNumber = enterpriseNumber
        self.elementID = elementID
        self.value = value
    }
    public var key: String { "\(enterpriseNumber):\(elementID)" }
}

/// Enrichment attached to a record at ingest time (what was known then).
public struct FlowEnrichment: Hashable, Sendable, Codable {
    public var direction: TrafficDirection = .unknown
    public var srcInternal = false
    public var dstInternal = false
    public var srcClientID: Int64?
    public var dstClientID: Int64?
    public var srcCountry: String?
    public var dstCountry: String?
    public var srcASN: UInt32?
    public var dstASN: UInt32?
    public var dstOrganization: String?
    public var service: String?
    public var enrichmentVersion: UInt16 = 0
    public init() {}
}

/// Normalized IPFIX flow record. Field names follow docs/schemas/README.md.
public struct FlowRecord: Hashable, Sendable, Codable, Identifiable {
    public static let schemaVersion: UInt16 = 1

    public var id: Int64 = 0           // flow_id, assigned by persistence
    public var origin: Origin = .live
    public var exporterID: Int32 = 0
    public var exporter: ExporterKey
    public var exportSequence: UInt32
    public var receivedAt: Timestamp
    public var exportTime: Timestamp
    public var startTime: Timestamp
    public var endTime: Timestamp
    public var clockSkewMicroseconds: Int64 = 0

    public var srcIP: IPAddress
    public var dstIP: IPAddress
    public var srcPort: UInt16 = 0
    public var dstPort: UInt16 = 0
    public var protocolNumber: UInt8 = 0
    public var tcpFlags: UInt16 = 0
    public var icmpType: UInt8?
    public var icmpCode: UInt8?
    public var packets: UInt64 = 0
    public var octets: UInt64 = 0
    public var reversePackets: UInt64?
    public var reverseOctets: UInt64?
    public var ingressInterface: UInt32?
    public var egressInterface: UInt32?
    public var srcVLAN: UInt16?
    public var dstVLAN: UInt16?
    public var flowDirection: UInt8?
    public var flowEndReason: UInt8?
    public var samplingInterval: UInt32?
    public var postNATSrcIP: IPAddress?
    public var postNATDstIP: IPAddress?
    public var postNATSrcPort: UInt16?
    public var postNATDstPort: UInt16?
    public var applicationID: String?
    public var extraElements: [RawInformationElement] = []
    public var enrichment = FlowEnrichment()

    public init(exporter: ExporterKey, exportSequence: UInt32, receivedAt: Timestamp, exportTime: Timestamp,
                startTime: Timestamp, endTime: Timestamp, srcIP: IPAddress, dstIP: IPAddress) {
        self.exporter = exporter
        self.exportSequence = exportSequence
        self.receivedAt = receivedAt
        self.exportTime = exportTime
        self.startTime = startTime
        self.endTime = endTime
        self.srcIP = srcIP
        self.dstIP = dstIP
    }

    public var ipVersion: UInt8 { srcIP.version }
    public var protocolName: String { IPProtocol.name(protocolNumber) }
    public var duration: Duration { endTime - startTime }
}
