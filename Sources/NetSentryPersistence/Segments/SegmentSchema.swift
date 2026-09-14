import DuckDB
import Foundation
import NetSentryCore

public enum SegmentKind: String, Sendable, Codable, CaseIterable { case flows, events }
public enum SegmentTier: String, Sendable, Codable, CaseIterable { case minute, hour, day }
public enum SegmentState: String, Sendable, Codable { case writing, finalized, compacting, missing, corrupt, deleted }

/// Column definitions for the two Parquet schemas (docs/schemas/README.md). The DDL is used for the
/// in-memory staging tables; Parquet files carry the same columns in the same order.
public enum SegmentSchema {
    public static let version: UInt16 = 1

    public static let flowColumns: [(String, String)] = [
        ("flow_id", "BIGINT"), ("origin", "UTINYINT"), ("exporter_id", "INTEGER"), ("exporter_addr", "VARCHAR"), ("observation_domain_id", "UINTEGER"),
        ("export_seq", "UINTEGER"), ("received_at", "BIGINT"), ("export_time", "BIGINT"), ("start_time", "BIGINT"), ("end_time", "BIGINT"),
        ("clock_skew_us", "BIGINT"), ("ip_version", "UTINYINT"), ("src_ip", "VARCHAR"), ("dst_ip", "VARCHAR"), ("src_v4", "UINTEGER"), ("dst_v4", "UINTEGER"),
        ("src_port", "USMALLINT"), ("dst_port", "USMALLINT"), ("protocol", "UTINYINT"), ("tcp_flags", "USMALLINT"), ("icmp_type", "UTINYINT"), ("icmp_code", "UTINYINT"),
        ("packets", "UBIGINT"), ("octets", "UBIGINT"), ("rev_packets", "UBIGINT"), ("rev_octets", "UBIGINT"), ("ingress_if", "UINTEGER"), ("egress_if", "UINTEGER"),
        ("src_vlan", "USMALLINT"), ("dst_vlan", "USMALLINT"), ("flow_direction", "UTINYINT"), ("flow_end_reason", "UTINYINT"), ("sampling_interval", "UINTEGER"),
        ("post_nat_src_ip", "VARCHAR"), ("post_nat_dst_ip", "VARCHAR"), ("post_nat_src_port", "USMALLINT"), ("post_nat_dst_port", "USMALLINT"), ("app_id", "VARCHAR"),
        ("ie_extra", "VARCHAR"), ("direction", "UTINYINT"), ("src_internal", "BOOLEAN"), ("dst_internal", "BOOLEAN"), ("src_client_id", "BIGINT"), ("dst_client_id", "BIGINT"),
        ("src_country", "VARCHAR"), ("dst_country", "VARCHAR"), ("src_asn", "UINTEGER"), ("dst_asn", "UINTEGER"), ("dst_org", "VARCHAR"), ("service", "VARCHAR"),
        ("flow_count", "UINTEGER"), ("enrichment_version", "USMALLINT"), ("schema_version", "USMALLINT"),
    ]

    public static let eventColumns: [(String, String)] = [
        ("event_id", "BIGINT"), ("origin", "UTINYINT"), ("received_at", "BIGINT"), ("event_time", "BIGINT"), ("time_inferred", "BOOLEAN"), ("source_ip", "VARCHAR"),
        ("transport", "UTINYINT"), ("syslog_version", "UTINYINT"), ("facility", "UTINYINT"), ("severity", "UTINYINT"), ("priority_present", "BOOLEAN"), ("hostname", "VARCHAR"),
        ("app_name", "VARCHAR"), ("proc_id", "VARCHAR"), ("msg_id", "VARCHAR"), ("structured_data", "VARCHAR"), ("message", "VARCHAR"), ("raw", "VARCHAR"), ("raw_bytes", "BLOB"),
        ("parser_name", "VARCHAR"), ("parser_version", "USMALLINT"), ("parse_status", "UTINYINT"), ("event_type", "UTINYINT"), ("src_ip", "VARCHAR"), ("dst_ip", "VARCHAR"),
        ("src_v4", "UINTEGER"), ("dst_v4", "UINTEGER"), ("src_port", "USMALLINT"), ("dst_port", "USMALLINT"), ("protocol", "UTINYINT"), ("action", "UTINYINT"),
        ("in_iface", "VARCHAR"), ("out_iface", "VARCHAR"), ("vlan", "USMALLINT"), ("rule_id", "VARCHAR"), ("rule_name", "VARCHAR"), ("username", "VARCHAR"), ("device_id", "VARCHAR"),
        ("ids_signature_id", "BIGINT"), ("ids_signature", "VARCHAR"), ("ids_category", "VARCHAR"), ("ids_severity", "UTINYINT"), ("src_client_id", "BIGINT"), ("dst_client_id", "BIGINT"),
        ("direction", "UTINYINT"), ("src_internal", "BOOLEAN"), ("dst_internal", "BOOLEAN"), ("dst_country", "VARCHAR"), ("dst_asn", "UINTEGER"), ("attrs", "VARCHAR"),
        ("enrichment_version", "USMALLINT"), ("schema_version", "USMALLINT"),
    ]

    public static func createTableSQL(_ kind: SegmentKind, name: String) -> String {
        let cols = (kind == .flows ? flowColumns : eventColumns).map { "\($0.0) \($0.1)" }.joined(separator: ", ")
        return "CREATE TABLE IF NOT EXISTS \(name) (\(cols))"
    }

    public static func columnNames(_ kind: SegmentKind) -> [String] { (kind == .flows ? flowColumns : eventColumns).map(\.0) }

    /// Time column used for ordering, partitioning and range pruning.
    public static func timeColumn(_ kind: SegmentKind) -> String { kind == .flows ? "start_time" : "received_at" }

    static let jsonEncoder: JSONEncoder = { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; return e }()

    static func json<T: Encodable>(_ v: T) -> String? {
        guard let d = try? jsonEncoder.encode(v) else { return nil }
        return String(decoding: d, as: UTF8.self)
    }

    /// Appends one flow in `flowColumns` order.
    public static func append(_ f: FlowRecord, exporterID: Int32, to a: Appender) throws {
        try a.append(f.id)
        try a.append(f.origin.rawValue)
        try a.append(exporterID)
        try a.append(f.exporter.address.description)
        try a.append(f.exporter.observationDomain)
        try a.append(f.exportSequence)
        try a.append(f.receivedAt.microseconds)
        try a.append(f.exportTime.microseconds)
        try a.append(f.startTime.microseconds)
        try a.append(f.endTime.microseconds)
        try a.append(f.clockSkewMicroseconds)
        try a.append(f.ipVersion)
        try a.append(f.srcIP.description)
        try a.append(f.dstIP.description)
        try a.append(f.srcIP.v4Value)
        try a.append(f.dstIP.v4Value)
        try a.append(f.srcPort)
        try a.append(f.dstPort)
        try a.append(f.protocolNumber)
        try a.append(f.tcpFlags)
        try a.append(f.icmpType)
        try a.append(f.icmpCode)
        try a.append(f.packets)
        try a.append(f.octets)
        try a.append(f.reversePackets)
        try a.append(f.reverseOctets)
        try a.append(f.ingressInterface)
        try a.append(f.egressInterface)
        try a.append(f.srcVLAN)
        try a.append(f.dstVLAN)
        try a.append(f.flowDirection)
        try a.append(f.flowEndReason)
        try a.append(f.samplingInterval)
        try a.append(f.postNATSrcIP?.description)
        try a.append(f.postNATDstIP?.description)
        try a.append(f.postNATSrcPort)
        try a.append(f.postNATDstPort)
        try a.append(f.applicationID)
        try a.append(f.extraElements.isEmpty ? nil : json(Dictionary(uniqueKeysWithValues: f.extraElements.map { ($0.key, $0.value.base64EncodedString()) })))
        try a.append(f.enrichment.direction.rawValue)
        try a.append(f.enrichment.srcInternal)
        try a.append(f.enrichment.dstInternal)
        try a.append(f.enrichment.srcClientID)
        try a.append(f.enrichment.dstClientID)
        try a.append(f.enrichment.srcCountry)
        try a.append(f.enrichment.dstCountry)
        try a.append(f.enrichment.srcASN)
        try a.append(f.enrichment.dstASN)
        try a.append(f.enrichment.dstOrganization)
        try a.append(f.enrichment.service)
        try a.append(UInt32(1))
        try a.append(f.enrichment.enrichmentVersion)
        try a.append(version)
        try a.endRow()
    }

    /// Appends one event in `eventColumns` order.
    public static func append(_ e: SyslogEvent, to a: Appender) throws {
        try a.append(e.id)
        try a.append(e.origin.rawValue)
        try a.append(e.receivedAt.microseconds)
        try a.append(e.eventTime?.microseconds)
        try a.append(e.timeInferred)
        try a.append(e.sourceIP.description)
        try a.append(e.transport.rawValue)
        try a.append(e.syslogVersion)
        try a.append(e.facility.rawValue)
        try a.append(e.severity.rawValue)
        try a.append(e.priorityPresent)
        try a.append(e.hostname)
        try a.append(e.appName)
        try a.append(e.procID)
        try a.append(e.msgID)
        try a.append(e.structuredData.isEmpty ? nil : json(e.structuredData))
        try a.append(e.message)
        try a.append(e.raw)
        try a.append(e.rawBytes)
        try a.append(e.parserName)
        try a.append(e.parserVersion)
        try a.append(e.parseStatus.rawValue)
        try a.append(e.eventType.rawValue)
        try a.append(e.srcIP?.description)
        try a.append(e.dstIP?.description)
        try a.append(e.srcIP?.v4Value)
        try a.append(e.dstIP?.v4Value)
        try a.append(e.srcPort)
        try a.append(e.dstPort)
        try a.append(e.protocolNumber)
        try a.append(e.action?.rawValue)
        try a.append(e.inInterface)
        try a.append(e.outInterface)
        try a.append(e.vlan)
        try a.append(e.ruleID)
        try a.append(e.ruleName)
        try a.append(e.username)
        try a.append(e.deviceID)
        try a.append(e.idsSignatureID)
        try a.append(e.idsSignature)
        try a.append(e.idsCategory)
        try a.append(e.idsSeverity)
        try a.append(e.enrichment.srcClientID)
        try a.append(e.enrichment.dstClientID)
        try a.append(e.enrichment.direction.rawValue)
        try a.append(e.enrichment.srcInternal)
        try a.append(e.enrichment.dstInternal)
        try a.append(e.enrichment.dstCountry)
        try a.append(e.enrichment.dstASN)
        try a.append(e.attributes.isEmpty ? nil : json(e.attributes))
        try a.append(e.enrichment.enrichmentVersion)
        try a.append(version)
        try a.endRow()
    }
}
