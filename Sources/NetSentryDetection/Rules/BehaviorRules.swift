import Foundation
import NetSentryCore

/// Beacon-like periodic outbound connections: many short flows to the same destination at a regular interval.
public struct BeaconingRule: DetectionRule {
    public let name = "beaconing"
    public let version = 1
    public let title = "Beacon-like periodic connections"
    public let description = "A client repeatedly connects to the same external destination at a nearly constant interval, which is typical of command-and-control check-ins and of many legitimate agents."
    public let defaultSeverity = AlertSeverity.medium
    public let parameters = [RuleParameter(key: "minConnections", label: "Minimum connections", value: 12, unit: "flows", help: "Connections to the same destination before the interval is analyzed."),
                             RuleParameter(key: "maxJitter", label: "Max jitter", value: 0.15, unit: "fraction", help: "Coefficient of variation of the intervals below which the pattern counts as periodic."),
                             RuleParameter(key: "maxBytes", label: "Max bytes per flow", value: 20_000, unit: "bytes", help: "Only small flows are considered beacons."),
                             RuleParameter(key: "window", label: "Window", value: 7200, unit: "seconds", help: "How far back connections are kept per destination.")]
    private var series: [String: [(Timestamp, Int64)]] = [:]
    private var alerted: [String: Timestamp] = [:]
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        var out: [Finding] = []
        let minN = Int(context.param("minConnections", self)), maxJitter = context.param("maxJitter", self), maxBytes = UInt64(context.param("maxBytes", self)), window = Int64(context.param("window", self) * 1_000_000)
        for f in flows where f.enrichment.direction == .outbound && f.octets <= maxBytes {
            guard let client = f.enrichment.srcClientID else { continue }
            let key = "\(client)>\(f.dstIP):\(f.dstPort)"
            var s = series[key] ?? []
            if let last = s.last, f.startTime.microseconds - last.0.microseconds < 1_000_000 { continue }   // same burst
            s.append((f.startTime, f.id))
            let cutoff = f.startTime.microseconds - window
            s.removeAll { $0.0.microseconds < cutoff }
            series[key] = s
            guard s.count >= minN else { continue }
            let intervals = zip(s, s.dropFirst()).map { Double($1.0.microseconds - $0.0.microseconds) / 1e6 }
            let mean = intervals.reduce(0, +) / Double(intervals.count)
            guard mean >= 5 else { continue }
            let variance = intervals.reduce(0) { $0 + ($1 - mean) * ($1 - mean) } / Double(intervals.count)
            let cv = variance.squareRoot() / mean
            guard cv <= maxJitter else { continue }
            if let a = alerted[key], f.startTime.microseconds - a.microseconds < window { continue }
            if context.expected("client", "\(client)", "destination", f.dstIP.description) || context.expected("global", "*", "beacon", f.dstIP.description) { continue }
            alerted[key] = f.startTime
            let cname = context.clientName(client)
            out.append(Finding(ruleName: name, ruleVersion: version, severity: defaultSeverity,
                               title: "\(cname) beacons to \(f.dstIP):\(f.dstPort) every \(Int(mean.rounded())) s",
                               summary: "\(s.count) small connections from \(cname) to \(f.dstIP):\(f.dstPort) at a steady \(Int(mean.rounded()))-second interval (jitter \(String(format: "%.0f", cv * 100)) %).",
                               explanation: "**Why:** the intervals between the last \(s.count) connections have a mean of \(String(format: "%.1f", mean)) s with a coefficient of variation of \(String(format: "%.2f", cv)) (threshold \(maxJitter)). Each flow carried ≤ \(Fmt.bytes(maxBytes)). Regular, small check-ins are characteristic of agents and malware alike; the destination decides which.\n\n**Destination:** \(f.dstIP):\(f.dstPort) \(f.protocolName)\(f.enrichment.dstOrganization.map { ", \($0)" } ?? "")\(f.enrichment.dstCountry.map { ", \($0)" } ?? "").",
                               occurredAt: f.startTime, clientID: client, entity: .init(kind: "ip", id: f.dstIP.description, label: f.dstIP.description),
                               evidence: ["destination": f.dstIP.description, "port": "\(f.dstPort)", "connections": "\(s.count)", "interval_s": String(format: "%.1f", mean), "cv": String(format: "%.3f", cv)],
                               baseline: Finding.Baseline(kind: "threshold", value: maxJitter, unit: "coefficient of variation", period: "\(Int(context.param("window", self))) s", samples: s.count),
                               flowIDs: s.map(\.1), steps: ["Identify the process on \(cname) (updaters, telemetry, cloud agents and security software all beacon).", "Look up the destination organization; if it is a known vendor, mark it expected."],
                               dedupeKey: "\(name):\(key)"))
        }
        return out
    }
}

/// Traffic between two internal networks/VLANs that are not expected to talk.
public struct UnexpectedVLANRule: DetectionRule {
    public let name = "unexpected-vlan-communication"
    public let version = 1
    public let title = "Communication between unexpected VLANs"
    public let description = "A flow crossed between two internal networks (VLANs) for which no expectation exists. Requires VLAN or network information on the records."
    public let defaultSeverity = AlertSeverity.medium
    public let parameters = [RuleParameter(key: "minBytes", label: "Minimum bytes", value: 1_000, unit: "bytes", help: "Ignore tiny cross-VLAN flows (broadcast, probes).")]
    private var alerted: Set<String> = []
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        var out: [Finding] = []
        let minBytes = UInt64(context.param("minBytes", self))
        for f in flows where f.enrichment.direction == .lan && f.octets >= minBytes {
            let srcNet = f.srcVLAN.map { "vlan\($0)" } ?? Self.network(of: f.srcIP, context)
            let dstNet = f.dstVLAN.map { "vlan\($0)" } ?? Self.network(of: f.dstIP, context)
            guard let s = srcNet, let d = dstNet, s != d else { continue }
            let pair = [s, d].sorted().joined(separator: "<->")
            if context.expected("global", "*", "vlan-pair", pair) || context.expected("vlan", s, "peer-vlan", d) || context.expected("vlan", d, "peer-vlan", s) { continue }
            let key = "\(f.srcIP)>\(f.dstIP):\(f.dstPort)"
            guard !alerted.contains(key) else { continue }
            alerted.insert(key)
            let client = f.enrichment.srcClientID
            let who = client.map(context.clientName) ?? f.srcIP.description
            out.append(Finding(ruleName: name, ruleVersion: version, severity: defaultSeverity,
                               title: "\(who) (\(s)) reached \(f.dstIP):\(f.dstPort) in \(d)",
                               summary: "Traffic crossed from \(s) to \(d) (\(Fmt.bytes(f.octets)) over \(f.protocolName) \(f.dstPort)); this pair of networks has no expectation.",
                               explanation: "**Why:** the flow's source belongs to \(s) and its destination to \(d) (from VLAN ids on the record or from your internal network definitions). No expectation marks this pair as allowed. Segmentation violations often show up first here.\n\n**Observed:** \(f.srcIP):\(f.srcPort) → \(f.dstIP):\(f.dstPort) \(f.protocolName), \(Fmt.bytes(f.octets)).",
                               occurredAt: f.endTime, clientID: client, entity: .init(kind: "vlan", id: pair, label: pair),
                               evidence: ["src_network": s, "dst_network": d, "destination": f.dstIP.description, "port": "\(f.dstPort)", "bytes": "\(f.octets)"],
                               flowIDs: [f.id], steps: ["Confirm the firewall policy between \(s) and \(d).", "If this path is intended, mark the VLAN pair as expected."],
                               dedupeKey: "\(name):\(pair):\(f.srcIP):\(f.dstIP):\(f.dstPort)"))
        }
        return out
    }

    static func network(of ip: IPAddress, _ ctx: DetectionContext) -> String? { ctx.internalPrefixes.first { $0.contains(ip) }?.description }
}

/// IDS/IPS syslog events, correlated with the flows of the same 5-tuple around the event time.
public struct IDSCorrelationRule: DetectionRule {
    public let name = "ids-event"
    public let version = 1
    public let title = "IDS/IPS event"
    public let description = "The gateway's intrusion detection reported a signature match; matching flows are attached as evidence."
    public let defaultSeverity = AlertSeverity.high
    public let parameters = [RuleParameter(key: "window", label: "Correlation window", value: 120, unit: "seconds", help: "Flows within this window of the event with the same addresses are attached."),
                             RuleParameter(key: "minPriority", label: "Minimum priority", value: 3, unit: "priority (1 = highest)", help: "Ignore signatures with a lower priority (higher number).")]
    private var recentFlows: [(FlowRecord)] = []
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        let window = Int64(context.param("window", self) * 1_000_000)
        recentFlows.append(contentsOf: flows)
        let cutoff = context.now.microseconds - window * 2
        if recentFlows.count > 50_000 || (recentFlows.first.map { $0.endTime.microseconds < cutoff } ?? false) { recentFlows.removeAll { $0.endTime.microseconds < cutoff } }
        var out: [Finding] = []
        let minPriority = Int(context.param("minPriority", self))
        for e in events where e.eventType == .ids {
            if let p = e.idsSeverity, Int(p) > minPriority { continue }
            let t = e.effectiveTime.microseconds
            // Flows between the same two endpoints are evidence; other activity of the host belongs to the timeline, not here.
            let related = recentFlows.filter { f in
                guard abs(f.endTime.microseconds - t) <= window else { return false }
                let ends: Set<IPAddress> = [f.srcIP, f.dstIP]
                switch (e.srcIP, e.dstIP) {
                case let (s?, d?): return ends.contains(s) && ends.contains(d)
                case let (s?, nil): return ends.contains(s)
                case let (nil, d?): return ends.contains(d)
                default: return false
                }
            }
            let internalIP = [e.srcIP, e.dstIP].compactMap { $0 }.first { context.isInternal($0) }
            let client = e.enrichment.srcClientID ?? e.enrichment.dstClientID
            let who = client.map(context.clientName) ?? internalIP?.description ?? "unknown client"
            let sev: AlertSeverity = (e.idsSeverity ?? 2) <= 1 ? .critical : ((e.idsSeverity ?? 2) == 2 ? .high : .medium)
            out.append(Finding(ruleName: name, ruleVersion: version, severity: sev,
                               title: "IDS: \(e.idsSignature ?? "signature \(e.idsSignatureID ?? 0)")\(e.action == .block ? " (blocked)" : "")",
                               summary: "\(e.idsCategory ?? "IDS event") involving \(who): \(e.srcIP?.description ?? "?")\(e.srcPort.map { ":\($0)" } ?? "") → \(e.dstIP?.description ?? "?")\(e.dstPort.map { ":\($0)" } ?? "")\(e.action == .block ? "; the gateway blocked it" : "").",
                               explanation: "**Why:** the gateway's IDS/IPS matched signature \(e.idsSignatureID.map { "`\($0)`" } ?? "")\(e.idsSignature.map { " \"\($0)\"" } ?? "") (category \(e.idsCategory ?? "n/a"), priority \(e.idsSeverity.map(String.init) ?? "n/a")). \(related.count) flow(s) between the same addresses within ±\(window / 1_000_000) s are attached; they show the surrounding traffic, not necessarily the exploit payload.\n\n**Raw event:** `\(e.message.prefix(300))`",
                               occurredAt: e.effectiveTime, clientID: client, entity: .init(kind: "ip", id: (e.srcIP ?? e.dstIP)?.description ?? "", label: who),
                               evidence: ["signature_id": e.idsSignatureID.map(String.init) ?? "", "signature": e.idsSignature ?? "", "category": e.idsCategory ?? "", "priority": e.idsSeverity.map(String.init) ?? "",
                                          "source": e.srcIP?.description ?? "", "destination": e.dstIP?.description ?? "", "action": e.action?.label ?? "", "related_flows": "\(related.count)"],
                               flowIDs: related.prefix(200).map(\.id), eventIDs: [e.id],
                               steps: ["Read the signature description (ET/Suricata rule id above) to understand what was matched.", "Review the attached flows and the client's activity before and after the event.", "If it was blocked and the client is internal, check the client for the software that triggered it."],
                               dedupeKey: "\(name):\(e.idsSignatureID ?? 0):\(e.srcIP?.description ?? ""):\(e.dstIP?.description ?? ""):\(t / 600_000_000)"))
        }
        return out
    }
}

/// Collection health as a detection: sustained drops, a down listener, or a silent exporter.
public struct CollectionFailureRule: DetectionRule {
    public let name = "collection-failure"
    public let version = 1
    public let title = "Collection failure or sustained packet loss"
    public let description = "The collector is dropping records, a listener is down, storage is paused, or an exporter went silent."
    public let defaultSeverity = AlertSeverity.high
    public let parameters = [RuleParameter(key: "dropThreshold", label: "Drops per tick", value: 100, unit: "records", help: "Receive-queue drops within one health tick that trigger an alert.")]
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] { [] }

    /// Called by the engine with the current health snapshot; not part of the record path.
    public func evaluate(health: HealthSnapshot, previous: HealthSnapshot?, context: DetectionContext) -> [Finding] {
        var out: [Finding] = []
        let drops = health.counters.receiveQueueDropped - (previous?.counters.receiveQueueDropped ?? 0)
        if Double(drops) >= context.param("dropThreshold", self) {
            out.append(Finding(ruleName: name, ruleVersion: version, severity: .high, title: "Collector dropped \(drops) records",
                               summary: "The receive queue overflowed and \(drops) datagrams were dropped since the last check; the affected period is recorded as a collection gap.",
                               explanation: "**Why:** downstream stages could not keep up (decode/persist queue depth \(health.queues.map { "\($0.name)=\($0.depth)/\($0.capacity)" }.joined(separator: ", "))). Data for this window is incomplete; absence of activity here must not be read as quiet.",
                               occurredAt: health.generatedAt, clientID: nil, entity: .init(kind: "collector", id: "receive", label: "Collector"),
                               evidence: ["dropped": "\(drops)", "datagrams_per_s": String(format: "%.0f", health.rates.datagramsPerSecond)], steps: ["Check CPU/disk pressure on the Mac.", "Reduce the gateway's export rate or raise the sampling interval."],
                               dedupeKey: "\(name):drops:\(health.generatedAt.seconds / 600)"))
        }
        for l in health.listeners { if case .failed(let reason) = l.state {
            out.append(Finding(ruleName: name, ruleVersion: version, severity: .critical, title: "\(l.kind.label) listener on \(l.transport.label) \(l.port) failed",
                               summary: reason, explanation: "**Why:** the listener could not bind or stopped; no \(l.kind.label) data is being received on that port. Recorded as a collection gap.",
                               occurredAt: health.generatedAt, clientID: nil, entity: .init(kind: "collector", id: l.id, label: "\(l.kind.label) \(l.port)"),
                               evidence: ["reason": reason], steps: ["Check for another process using the port.", "Review listener settings."], dedupeKey: "\(name):listener:\(l.id)"))
        } }
        if let s = health.storage, s.ingestionPaused {
            out.append(Finding(ruleName: name, ruleVersion: version, severity: .critical, title: "Ingestion paused: disk nearly full",
                               summary: "Free space \(Fmt.bytes(s.freeBytesOnVolume)) is below the safety threshold \(Fmt.bytes(s.safetyThresholdBytes)).",
                               explanation: "**Why:** NetSentry never fills the volume. New records are buffered briefly and then dropped until space returns; the period is recorded as a gap.",
                               occurredAt: health.generatedAt, clientID: nil, entity: .init(kind: "collector", id: "storage", label: "Storage"),
                               evidence: ["free": "\(s.freeBytesOnVolume)", "threshold": "\(s.safetyThresholdBytes)"], steps: ["Free disk space or lower the storage budget."], dedupeKey: "\(name):disk"))
        }
        for w in health.warnings where w.id.hasPrefix("silent-") {
            out.append(Finding(ruleName: name, ruleVersion: version, severity: .medium, title: w.title, summary: w.detail,
                               explanation: "**Why:** a previously active exporter has not sent anything for over five minutes while the listener is up. The gateway may have stopped exporting, changed address, or lost the route.",
                               occurredAt: health.generatedAt, clientID: nil, entity: .init(kind: "exporter", id: w.id, label: w.title), evidence: ["since": "\(w.since)"],
                               steps: ["Check the gateway's NetFlow/syslog settings and the Mac's address."], dedupeKey: "\(name):\(w.id):\(w.since.seconds)"))
        }
        return out
    }
}
