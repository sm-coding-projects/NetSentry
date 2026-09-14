import Foundation
import NetSentryCore

/// First contact between an internal client and an external destination / country / ASN / service.
/// Findings are scoped per client (a NAS talking to a new ASN is interesting even if a laptop already did).
public struct FirstSeenRule: DetectionRule {
    public enum Kind: String, Sendable { case destination, country, asn, service }
    public let kind: Kind
    public var name: String { "first-seen-\(kind.rawValue)" }
    public let version = 1
    public var title: String {
        switch kind { case .destination: "First-seen external destination"; case .country: "First-seen country"; case .asn: "First-seen ASN"; case .service: "First-seen service or port" }
    }
    public var description: String {
        switch kind {
        case .destination: "An internal client contacted a public address it never contacted before (after the learning period)."
        case .country: "An internal client sent traffic to a country it never contacted before."
        case .asn: "An internal client sent traffic to an autonomous system (network operator) it never contacted before."
        case .service: "An internal client used a destination port/protocol it never used before."
        }
    }
    public var defaultSeverity: AlertSeverity { kind == .destination ? .info : .low }
    public var parameters: [RuleParameter] {
        [RuleParameter(key: "learningDays", label: "Learning period", value: 3, unit: "days", help: "No alerts while a client is younger than this; its history is only recorded."),
         RuleParameter(key: "minBytes", label: "Minimum bytes", value: kind == .destination ? 10_000 : 1, unit: "bytes", help: "Ignore tiny first contacts (probes, single packets).")]
    }
    private var clientFirstSeen: [Int64: Timestamp] = [:]
    public init(kind: Kind) { self.kind = kind }

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        var out: [Finding] = []
        let learning = Int64(context.param("learningDays", self) * 86_400_000_000)
        let minBytes = UInt64(context.param("minBytes", self))
        for f in flows where f.enrichment.direction == .outbound {
            guard let client = f.enrichment.srcClientID else { continue }
            let key: String, label: String, entity: Finding.Entity, expectedKind: String
            switch kind {
            case .destination: key = f.dstIP.description; label = key; entity = .init(kind: "ip", id: key, label: key); expectedKind = "destination"
            case .country: guard let c = f.enrichment.dstCountry else { continue }; key = c; label = c; entity = .init(kind: "country", id: c, label: c); expectedKind = "country"
            case .asn: guard let a = f.enrichment.dstASN else { continue }; key = "\(a)"; label = "AS\(a)" + (f.enrichment.dstOrganization.map { " (\($0))" } ?? ""); entity = .init(kind: "asn", id: key, label: label); expectedKind = "asn"
            case .service: key = "\(f.protocolName.lowercased())/\(f.dstPort)"; label = f.enrichment.service.map { "\($0) (\(key))" } ?? key; entity = .init(kind: "port", id: key, label: label); expectedKind = "port"
            }
            let isNew = try state.firstSeen(scopeType: "client", scopeValue: "\(client)", kind: kind.rawValue, key: key, at: f.endTime)
            guard isNew else { continue }
            // Learning period: the client's own first observation anchors it.
            let clientStart: Timestamp
            if let c = clientFirstSeen[client] { clientStart = c } else {
                if let s = try state.get(rule: name, key: "client-start-\(client)") { clientStart = Timestamp(microseconds: Int64(s) ?? f.endTime.microseconds) } else { clientStart = f.endTime; try state.set(rule: name, key: "client-start-\(client)", value: "\(f.endTime.microseconds)") }
                clientFirstSeen[client] = clientStart
            }
            guard f.endTime.microseconds - clientStart.microseconds >= learning else { continue }
            guard f.octets >= minBytes else { continue }
            if context.expected("client", "\(client)", expectedKind, key) || context.expected("global", "*", expectedKind, key) { continue }
            let cname = context.clientName(client)
            out.append(Finding(
                ruleName: name, ruleVersion: version, severity: defaultSeverity,
                title: "\(cname) contacted a new \(kind.rawValue): \(label)",
                summary: "\(cname) sent \(Fmt.bytes(f.octets)) to \(label) over \(f.protocolName) \(f.dstPort); no earlier contact was recorded.",
                explanation: "**Why:** this is the first flow from \(cname) to \(kind == .service ? "port" : kind.rawValue) `\(label)` since NetSentry started tracking this client (\(Fmt.time(clientStart))). The learning period of \(Int(context.param("learningDays", self))) days had passed.\n\n**Observed:** \(f.srcIP):\(f.srcPort) → \(f.dstIP):\(f.dstPort) \(f.protocolName), \(f.packets) packets, \(Fmt.bytes(f.octets)), at \(Fmt.time(f.endTime)).",
                occurredAt: f.endTime, clientID: client, entity: entity,
                evidence: ["destination": f.dstIP.description, "port": "\(f.dstPort)", "protocol": f.protocolName, "bytes": "\(f.octets)", "packets": "\(f.packets)",
                           "country": f.enrichment.dstCountry ?? "", "asn": f.enrichment.dstASN.map(String.init) ?? "", "organization": f.enrichment.dstOrganization ?? ""],
                baseline: Finding.Baseline(kind: "first-seen", value: 0, unit: "prior contacts", period: "client lifetime", samples: 0),
                flowIDs: [f.id], steps: ["Check whether \(cname) should be talking to \(label) (software update, new service, user action).",
                                         "Open the client's timeline around \(Fmt.time(f.endTime)) for related DNS, firewall or IDS events.",
                                         "If this is expected, mark the \(kind.rawValue) as expected for \(cname) to stop future alerts."],
                dedupeKey: "\(name):\(client):\(key)"))
        }
        return out
    }
}
