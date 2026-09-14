import Foundation
import NetSentryCore

/// DNS traffic to a resolver that is not in the trusted list (DoT port 853 included; DoH is invisible here).
public struct UnauthorizedResolverRule: DetectionRule {
    public let name = "dns-unauthorized-resolver"
    public let version = 1
    public let title = "DNS to an unauthorized resolver"
    public let description = "A client sent DNS (port 53 or DNS-over-TLS 853) to a resolver that is not in the trusted list."
    public let defaultSeverity = AlertSeverity.medium
    public let parameters = [RuleParameter(key: "minFlows", label: "Minimum flows", value: 1, unit: "flows", help: "Alert after this many flows to the same resolver.")]
    private var counts: [String: Int] = [:]
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        guard !context.trustedResolvers.isEmpty else { return [] }
        var out: [Finding] = []
        for f in flows where (f.dstPort == 53 || f.dstPort == 853) && f.enrichment.direction != .inbound {
            guard !context.trustedResolvers.contains(f.dstIP), let client = f.enrichment.srcClientID else { continue }
            if context.expected("client", "\(client)", "resolver", f.dstIP.description) || context.expected("global", "*", "resolver", f.dstIP.description) { continue }
            let key = "\(client):\(f.dstIP)"
            counts[key, default: 0] += 1
            guard counts[key]! >= Int(context.param("minFlows", self)) else { continue }
            let cname = context.clientName(client)
            out.append(Finding(ruleName: name, ruleVersion: version, severity: defaultSeverity,
                               title: "\(cname) is using DNS resolver \(f.dstIP)",
                               summary: "\(cname) sent \(f.dstPort == 853 ? "DNS-over-TLS" : "DNS") to \(f.dstIP), which is not a trusted resolver.",
                               explanation: "**Why:** trusted resolvers are \(context.trustedResolvers.map(\.description).sorted().joined(separator: ", ")). Traffic to any other address on port 53/853 bypasses your configured DNS filtering/logging.\n\n**Observed:** \(counts[key]!) flow(s) from \(f.srcIP) to \(f.dstIP):\(f.dstPort) \(f.protocolName), latest \(Fmt.time(f.endTime)).",
                               occurredAt: f.endTime, clientID: client, entity: .init(kind: "ip", id: f.dstIP.description, label: f.dstIP.description),
                               evidence: ["resolver": f.dstIP.description, "port": "\(f.dstPort)", "flows": "\(counts[key]!)", "bytes": "\(f.octets)"],
                               baseline: Finding.Baseline(kind: "threshold", value: context.param("minFlows", self), unit: "flows", period: "since start", samples: counts[key]!),
                               flowIDs: [f.id], steps: ["Check the client's DNS settings (manually configured resolver, VPN, or an app with its own DoT).", "If this resolver is acceptable, add it to trusted resolvers or mark it expected for this client."],
                               dedupeKey: "\(name):\(key)"))
        }
        return out
    }
}

/// Horizontal (many hosts, one port) and vertical (one host, many ports) scans within a sliding window.
public struct PortScanRule: DetectionRule {
    public enum Kind: String, Sendable { case horizontal, vertical }
    public let kind: Kind
    public var name: String { "port-scan-\(kind.rawValue)" }
    public let version = 1
    public var title: String { kind == .horizontal ? "Horizontal port scan" : "Vertical port scan" }
    public var description: String { kind == .horizontal ? "One source contacted many distinct hosts on the same port within a short window." : "One source contacted many distinct ports on the same host within a short window." }
    public let defaultSeverity = AlertSeverity.high
    public var parameters: [RuleParameter] {
        [RuleParameter(key: "window", label: "Window", value: 60, unit: "seconds", help: "Sliding window length."),
         RuleParameter(key: "threshold", label: "Distinct targets", value: kind == .horizontal ? 25 : 20, unit: kind == .horizontal ? "hosts" : "ports", help: "Distinct targets within the window that trigger an alert."),
         RuleParameter(key: "maxPackets", label: "Max packets per flow", value: 4, unit: "packets", help: "Only small flows (probes) count; established sessions are ignored.")]
    }
    private struct Window { var events: [(t: Timestamp, target: String)] = []; var flowIDs: [Int64] = [] }
    private var windows: [String: Window] = [:]
    private var alerted: [String: Timestamp] = [:]
    public init(kind: Kind) { self.kind = kind }

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        var out: [Finding] = []
        let window = Int64(context.param("window", self) * 1_000_000)
        let threshold = Int(context.param("threshold", self))
        let maxPackets = UInt64(context.param("maxPackets", self))
        for f in flows where f.packets <= maxPackets && (f.protocolNumber == 6 || f.protocolNumber == 17) {
            let key = kind == .horizontal ? "\(f.srcIP)|\(f.protocolNumber)/\(f.dstPort)" : "\(f.srcIP)|\(f.dstIP)"
            let target = kind == .horizontal ? f.dstIP.description : "\(f.dstPort)"
            var w = windows[key] ?? Window()
            w.events.append((f.endTime, target)); w.flowIDs.append(f.id)
            let cutoff = f.endTime.microseconds - window
            while let first = w.events.first, first.t.microseconds < cutoff { w.events.removeFirst(); if !w.flowIDs.isEmpty { w.flowIDs.removeFirst() } }
            let distinct = Set(w.events.map(\.target))
            windows[key] = w
            if distinct.count >= threshold, alerted[key].map({ f.endTime.microseconds - $0.microseconds > window }) ?? true {
                alerted[key] = f.endTime
                let client = f.enrichment.srcClientID
                let who = client.map(context.clientName) ?? f.srcIP.description
                let what = kind == .horizontal ? "\(distinct.count) hosts on \(f.protocolName) port \(f.dstPort)" : "\(distinct.count) ports on \(f.dstIP)"
                out.append(Finding(ruleName: name, ruleVersion: version, severity: context.isInternal(f.srcIP) ? .high : .medium,
                                   title: "\(who) scanned \(what)",
                                   summary: "\(who) sent short probes to \(what) within \(Int(context.param("window", self))) s.",
                                   explanation: "**Why:** \(distinct.count) distinct \(kind == .horizontal ? "destination hosts" : "destination ports") were contacted by \(f.srcIP) within the \(Int(context.param("window", self)))-second window, above the threshold of \(threshold). Only flows with ≤ \(maxPackets) packets were counted, so normal sessions do not contribute.\n\n**Sample targets:** \(distinct.sorted().prefix(10).joined(separator: ", "))\(distinct.count > 10 ? ", …" : "").",
                                   occurredAt: f.endTime, clientID: client, entity: .init(kind: "ip", id: f.srcIP.description, label: who),
                                   evidence: ["source": f.srcIP.description, "distinct": "\(distinct.count)", "window_s": "\(Int(context.param("window", self)))", kind == .horizontal ? "port" : "host": kind == .horizontal ? "\(f.dstPort)" : f.dstIP.description],
                                   baseline: Finding.Baseline(kind: "threshold", value: Double(threshold), unit: kind == .horizontal ? "hosts" : "ports", period: "\(Int(context.param("window", self))) s", samples: distinct.count),
                                   flowIDs: Array(w.flowIDs.suffix(200)),
                                   steps: ["Identify the process on \(who) generating the probes (security scanner, malware, misconfigured monitoring).", "Check firewall events for the same source in the Investigation timeline.", "If this is an authorized scanner, mark the behavior as expected for the client."],
                                   dedupeKey: "\(name):\(key)"))
            }
        }
        return out
    }
}
