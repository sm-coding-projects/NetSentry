import Foundation
import NetSentryCore

public struct IPFIXMessageHeader: Sendable, Hashable {
    public static let size = 16
    public let version: UInt16
    public let length: UInt16
    public let exportTime: UInt32       // seconds since epoch
    public let sequenceNumber: UInt32   // count of data records previously sent (RFC 7011 §3.1)
    public let observationDomainID: UInt32
}

public struct TemplateField: Sendable, Hashable, Codable {
    public static let variableLength: UInt16 = 65535
    public let elementID: UInt16
    public let enterpriseNumber: UInt32     // 0 = IANA
    public let length: UInt16
    public init(elementID: UInt16, enterpriseNumber: UInt32 = 0, length: UInt16) {
        self.elementID = elementID; self.enterpriseNumber = enterpriseNumber; self.length = length
    }
    public var isVariableLength: Bool { length == Self.variableLength }
    public var isReverse: Bool { enterpriseNumber == IANAInformationElements.reversePEN }
    public var name: String {
        if enterpriseNumber == 0 || isReverse {
            let base = IANAInformationElements.info(elementID)?.name ?? "ie\(elementID)"
            return isReverse ? "reverse_\(base)" : base
        }
        return "pen\(enterpriseNumber)_ie\(elementID)"
    }
}

public enum TemplateKind: String, Sendable, Codable { case data, options }

public struct IPFIXTemplate: Sendable, Hashable, Codable {
    public let id: UInt16
    public let kind: TemplateKind
    public let scopeFieldCount: Int
    public let fields: [TemplateField]
    public var receivedAt: Timestamp
    public var lastRefreshed: Timestamp
    public var refreshCount: Int

    public init(id: UInt16, kind: TemplateKind, scopeFieldCount: Int, fields: [TemplateField], receivedAt: Timestamp) {
        self.id = id; self.kind = kind; self.scopeFieldCount = scopeFieldCount; self.fields = fields
        self.receivedAt = receivedAt; self.lastRefreshed = receivedAt; self.refreshCount = 0
    }
    public var hasVariableLengthFields: Bool { fields.contains { $0.isVariableLength } }
    /// Minimum encoded record length (variable-length fields count as 1 byte).
    public var minimumRecordLength: Int { fields.reduce(0) { $0 + ($1.isVariableLength ? 1 : Int($1.length)) } }
    /// Same field list (ignoring timestamps) → a refresh rather than a replacement.
    public func isEquivalent(to other: IPFIXTemplate) -> Bool { kind == other.kind && scopeFieldCount == other.scopeFieldCount && fields == other.fields }
}

/// A decoded field value. Numeric interpretation happens at normalization time; the raw bytes are kept.
public struct DecodedField: Sendable, Hashable {
    public let field: TemplateField
    public let bytes: Data
    public var unsigned: UInt64? {
        guard bytes.count >= 1, bytes.count <= 8 else { return nil }
        return bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }
    public var ipAddress: IPAddress? { IPAddress(bytes: bytes) }
    /// UTF-8 string with NUL padding removed (exporters pad fixed-length strings with NULs).
    public var string: String? {
        let trimmed = bytes.drop { $0 == 0 }.prefix { $0 != 0 }
        return String(bytes: trimmed, encoding: .utf8)
    }
}

public struct IPFIXOptionsRecord: Sendable, Hashable {
    public let exporter: ExporterKey
    public let templateID: UInt16
    public let receivedAt: Timestamp
    public let scope: [DecodedField]
    public let values: [DecodedField]
    public func value(_ id: UInt16, pen: UInt32 = 0) -> DecodedField? { (scope + values).first { $0.field.elementID == id && $0.field.enterpriseNumber == pen } }
}

/// Sampling parameters learned from options records (PSAMP) or samplingInterval (IE 34).
public struct SamplingInfo: Sendable, Hashable, Codable {
    public var selectorID: UInt64?
    public var algorithm: UInt16?
    public var size: UInt32?
    public var population: UInt32?
    public var packetInterval: UInt32?
    public var packetSpace: UInt32?
    public var legacyInterval: UInt32?
    /// Estimated "1 in N" packet sampling rate.
    public var rate: UInt32? {
        if let s = size, let p = population, s > 0 { return max(1, p / s) }
        if let i = packetInterval, let sp = packetSpace { return max(1, i + sp) }
        if let i = packetInterval, i > 0 { return i }
        if let l = legacyInterval, l > 0 { return l }
        return nil
    }
}

/// Everything notable that happened while decoding one datagram. The decode stage maps these onto
/// health counters and exporter state; nothing here is dropped silently.
public enum IPFIXEvent: Sendable, Hashable {
    case unsupportedVersion(UInt16)
    case malformed(String)
    case templateAdded(exporter: ExporterKey, template: UInt16, kind: TemplateKind, fieldCount: Int)
    case templateRefreshed(exporter: ExporterKey, template: UInt16)
    case templateReplaced(exporter: ExporterKey, template: UInt16, fieldCount: Int)
    case templateWithdrawn(exporter: ExporterKey, template: UInt16)
    case templateExpired(exporter: ExporterKey, template: UInt16)
    case templateRejected(exporter: ExporterKey, template: UInt16, reason: String)
    case missingTemplate(exporter: ExporterKey, template: UInt16, bytes: Int, buffered: Bool)
    case pendingDecoded(exporter: ExporterKey, template: UInt16, records: Int)
    case pendingDropped(exporter: ExporterKey, template: UInt16, sets: Int, reason: String)
    case sequenceGap(exporter: ExporterKey, expected: UInt32, received: UInt32, missingRecords: Int64)
    case exporterRestart(exporter: ExporterKey, reason: String)
    case exporterSeen(exporter: ExporterKey, first: Bool)
    case clockSkew(exporter: ExporterKey, skewMicroseconds: Int64)
    case samplingLearned(exporter: ExporterKey, info: SamplingInfo)
    case observationDomainName(exporter: ExporterKey, name: String)
    case interfaceName(exporter: ExporterKey, index: UInt32, name: String, description: String?)
}

public struct IPFIXDecodeResult: Sendable {
    public var flows: [FlowRecord] = []
    public var options: [IPFIXOptionsRecord] = []
    public var events: [IPFIXEvent] = []
    public var dataRecordCount = 0
    public var header: IPFIXMessageHeader?
    public init() {}
}

public struct IPFIXExporterState: Sendable, Hashable {
    public let key: ExporterKey
    public var firstSeen: Timestamp
    public var lastSeen: Timestamp
    public var messages: UInt64 = 0
    public var records: UInt64 = 0
    public var lastSequence: UInt32?
    public var expectedSequence: UInt32?
    public var sequenceGaps: UInt64 = 0
    public var restarts: UInt64 = 0
    public var templates: [UInt16: IPFIXTemplate] = [:]
    public var pendingSets = 0
    public var pendingBytes = 0
    public var clockSkewMicroseconds: Int64?
    public var systemInitTime: Timestamp?
    public var observationDomainName: String?
    public var interfaceNames: [UInt32: String] = [:]
    public var sampling: [UInt64: SamplingInfo] = [:]     // by selectorId
    public var defaultSampling: SamplingInfo?
}
