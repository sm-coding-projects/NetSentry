import Foundation
import NetSentryCore

/// Flat, documented representation of a flow for JSON/CSV. Field names are stable (see docs/exports.md).
public struct ExportedFlow: Codable, Sendable {
    public var id: Int64, start: String, end: String, src: String, srcPort: UInt16, dst: String, dstPort: UInt16, proto: UInt8, protoName: String
    public var packets: UInt64, bytes: UInt64, direction: String, service: String, srcClient: Int64?, dstClient: Int64?, dstCountry: String, dstASN: UInt32?, dstOrg: String
    public var exporter: String, sampled: Bool

    public static let csvHeader = ["id", "start", "end", "src", "src_port", "dst", "dst_port", "proto", "proto_name", "packets", "bytes", "direction", "service", "src_client", "dst_client", "dst_country", "dst_asn", "dst_org", "exporter", "sampled"]
    public var csvFields: [String] {
        ["\(id)", start, end, src, "\(srcPort)", dst, "\(dstPort)", "\(proto)", protoName, "\(packets)", "\(bytes)", direction, service, srcClient.map { "\($0)" } ?? "", dstClient.map { "\($0)" } ?? "",
         dstCountry, dstASN.map { "\($0)" } ?? "", dstOrg, exporter, sampled ? "true" : "false"]
    }

    public init(_ f: FlowRecord, redactor r: Redactor) {
        id = f.id; start = ISO.string(f.startTime); end = ISO.string(f.endTime)
        src = r.address(f.srcIP, isInternal: f.enrichment.srcInternal); srcPort = f.srcPort
        dst = r.address(f.dstIP, isInternal: f.enrichment.dstInternal); dstPort = f.dstPort
        proto = f.protocolNumber; protoName = f.protocolName; packets = f.packets; bytes = f.octets
        direction = f.enrichment.direction.label.lowercased(); service = f.enrichment.service ?? ""
        srcClient = f.enrichment.srcClientID; dstClient = f.enrichment.dstClientID
        dstCountry = f.enrichment.dstCountry ?? ""; dstASN = f.enrichment.dstASN; dstOrg = f.enrichment.dstOrganization ?? ""
        exporter = r.address(f.exporter.address, isInternal: true) + "/\(f.exporter.observationDomain)"
        sampled = (f.samplingInterval ?? 1) > 1
    }
}

public struct ExportedEvent: Codable, Sendable {
    public var id: Int64, time: String, timeInferred: Bool, source: String, facility: String, severity: String, host: String, app: String, type: String, action: String
    public var src: String, srcPort: UInt16?, dst: String, dstPort: UInt16?, proto: UInt8?, rule: String, ids: String, idsCategory: String, idsSeverity: UInt8?, user: String, device: String
    public var parser: String, status: String, message: String, raw: String

    public static let csvHeader = ["id", "time", "time_inferred", "source", "facility", "severity", "host", "app", "type", "action", "src", "src_port", "dst", "dst_port", "proto", "rule", "ids_signature", "ids_category", "ids_severity", "user", "device", "parser", "status", "message", "raw"]
    public var csvFields: [String] {
        ["\(id)", time, timeInferred ? "true" : "false", source, facility, severity, host, app, type, action, src, srcPort.map { "\($0)" } ?? "", dst, dstPort.map { "\($0)" } ?? "", proto.map { "\($0)" } ?? "",
         rule, ids, idsCategory, idsSeverity.map { "\($0)" } ?? "", user, device, parser, status, message, raw]
    }

    public init(_ e: SyslogEvent, redactor r: Redactor, isInternal: (IPAddress) -> Bool) {
        id = e.id; time = ISO.string(e.effectiveTime); timeInferred = e.timeInferred
        source = r.address(e.sourceIP, isInternal: true); facility = String(describing: e.facility); severity = String(describing: e.severity)
        host = r.hostname(e.hostname); app = e.appName ?? ""; type = e.eventType.label; action = e.action.map { String(describing: $0) } ?? ""
        src = r.address(e.srcIP, isInternal: e.enrichment.srcInternal); srcPort = e.srcPort
        dst = r.address(e.dstIP, isInternal: e.enrichment.dstInternal); dstPort = e.dstPort; proto = e.protocolNumber
        rule = e.ruleName ?? e.ruleID ?? ""; ids = e.idsSignature ?? ""; idsCategory = e.idsCategory ?? ""; idsSeverity = e.idsSeverity
        user = r.username(e.username); device = r.mac(e.deviceID)
        parser = "\(e.parserName) v\(e.parserVersion)"; status = String(describing: e.parseStatus)
        message = r.text(e.message, isInternal: isInternal); raw = r.policy.dropRawMessages ? "" : r.text(e.raw ?? "", isInternal: isInternal)
    }
}

public enum RecordExport {
    static let encoder: JSONEncoder = { let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]; return e }()

    public static func flowsCSV(_ flows: [FlowRecord], policy: RedactionPolicy) -> String {
        let r = Redactor(policy)
        var out = CSV.line(ExportedFlow.csvHeader)
        for f in flows { out += CSV.line(ExportedFlow(f, redactor: r).csvFields) }
        return out
    }
    public static func flowsJSON(_ flows: [FlowRecord], policy: RedactionPolicy) throws -> Data {
        let r = Redactor(policy)
        return try encoder.encode(Envelope(kind: "flows", redaction: policy.summary, count: flows.count, records: flows.map { ExportedFlow($0, redactor: r) }))
    }
    public static func eventsCSV(_ events: [SyslogEvent], policy: RedactionPolicy, isInternal: (IPAddress) -> Bool) -> String {
        let r = Redactor(policy)
        var out = CSV.line(ExportedEvent.csvHeader)
        for e in events { out += CSV.line(ExportedEvent(e, redactor: r, isInternal: isInternal).csvFields) }
        return out
    }
    public static func eventsJSON(_ events: [SyslogEvent], policy: RedactionPolicy, isInternal: (IPAddress) -> Bool) throws -> Data {
        let r = Redactor(policy)
        return try encoder.encode(Envelope(kind: "events", redaction: policy.summary, count: events.count, records: events.map { ExportedEvent($0, redactor: r, isInternal: isInternal) }))
    }

    public struct Envelope<T: Codable & Sendable>: Codable, Sendable {
        public var format = "netsentry-export/1"
        public var product = Branding.productName
        public var generatedAt = ISO.string(.now)
        public var kind: String
        public var redaction: String
        public var count: Int
        public var records: [T]
    }
}
