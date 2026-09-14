import Foundation
import NetSentryCore
import NetSentryPersistence

/// Applies client identity, GeoIP/ASN and service names to records. Version 2 = identity + GeoIP.
public actor Enricher {
    public static let version: UInt16 = 2
    private let resolver: EntityResolver
    private var geo: MMDBReader?
    private var asn: MMDBReader?
    private var geoCache: [IPAddress: MMDBReader.GeoResult] = [:]

    public init(resolver: EntityResolver, geoDatabasePath: String? = nil, asnDatabasePath: String? = nil) {
        self.resolver = resolver
        if let p = geoDatabasePath { geo = try? MMDBReader(path: p) }
        if let p = asnDatabasePath { asn = try? MMDBReader(path: p) }
    }

    public func setDatabases(geoPath: String?, asnPath: String?) {
        geo = geoPath.flatMap { try? MMDBReader(path: $0) }
        asn = asnPath.flatMap { try? MMDBReader(path: $0) }
        geoCache.removeAll()
    }

    public var hasGeoIP: Bool { geo != nil || asn != nil }

    private func lookup(_ ip: IPAddress) -> MMDBReader.GeoResult {
        if let c = geoCache[ip] { return c }
        var r = MMDBReader.GeoResult()
        if !ip.isNonRoutable {
            if let g = geo?.geo(ip) { r.countryISO = g.countryISO; r.asn = g.asn; r.organization = g.organization }
            if r.asn == nil, let a = asn?.geo(ip) { r.asn = a.asn; r.organization = a.organization }
        }
        if geoCache.count > 100_000 { geoCache.removeAll() }
        geoCache[ip] = r
        return r
    }

    public func enrich(_ f: inout FlowRecord) async {
        let srcMAC = f.extraElements.first { $0.enterpriseNumber == 0 && $0.elementID == 56 }.map { $0.value.map { String(format: "%02x", $0) }.joined(separator: ":") }
        if f.enrichment.srcInternal { f.enrichment.srcClientID = try? await resolver.observe(ip: f.srcIP, mac: srcMAC, vlan: f.srcVLAN, at: f.endTime, source: "ipfix") }
        if f.enrichment.dstInternal { f.enrichment.dstClientID = try? await resolver.observe(ip: f.dstIP, vlan: f.dstVLAN, at: f.endTime, source: "ipfix") }
        if !f.enrichment.dstInternal { let g = lookup(f.dstIP); f.enrichment.dstCountry = g.countryISO; f.enrichment.dstASN = g.asn; f.enrichment.dstOrganization = g.organization }
        if !f.enrichment.srcInternal { let g = lookup(f.srcIP); f.enrichment.srcCountry = g.countryISO; f.enrichment.srcASN = g.asn }
        f.enrichment.service = ServiceNames.name(port: f.dstPort, protocolNumber: f.protocolNumber) ?? ServiceNames.name(port: f.srcPort, protocolNumber: f.protocolNumber)
        f.enrichment.enrichmentVersion = Self.version
    }

    public func enrich(_ e: inout SyslogEvent) async {
        let t = e.effectiveTime
        if e.eventType == .dhcp, let ip = e.srcIP, e.attributes["dhcp.message"] == "ACK" {
            e.enrichment.srcClientID = try? await resolver.observe(ip: ip, mac: e.deviceID, hostname: e.attributes["dhcp.hostname"], at: t, source: "dhcp")
        } else if let ip = e.srcIP, e.enrichment.srcInternal {
            e.enrichment.srcClientID = try? await resolver.observe(ip: ip, mac: e.eventType == .firewall ? e.deviceID : nil, at: t, source: e.eventType.rawValue == 1 ? "firewall" : "syslog")
        }
        if let ip = e.dstIP, e.enrichment.dstInternal { e.enrichment.dstClientID = try? await resolver.observe(ip: ip, at: t, source: "syslog") }
        if let ip = e.dstIP, !e.enrichment.dstInternal { let g = lookup(ip); e.enrichment.dstCountry = g.countryISO; e.enrichment.dstASN = g.asn }
        e.enrichment.enrichmentVersion = Self.version
    }
}
