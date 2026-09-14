import Foundation
import NetSentryCore

/// Repeated denied connections from one source to one destination/port.
public struct RepeatedDenialsRule: DetectionRule {
    public let name = "repeated-denials"
    public let version = 1
    public let title = "Repeated denied connections"
    public let description = "The firewall denied the same source → destination:port combination many times within a window."
    public let defaultSeverity = AlertSeverity.low
    public let parameters = [RuleParameter(key: "threshold", label: "Denials", value: 20, unit: "events", help: "Denied events for the same tuple within the window."),
                             RuleParameter(key: "window", label: "Window", value: 300, unit: "seconds", help: "Sliding window length.")]
    private var windows: [String: [(Timestamp, Int64)]] = [:]
    private var alerted: [String: Timestamp] = [:]
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        var out: [Finding] = []
        let window = Int64(context.param("window", self) * 1_000_000), threshold = Int(context.param("threshold", self))
        for e in events where e.eventType == .firewall && (e.action == .deny || e.action == .reject) {
            guard let src = e.srcIP, let dst = e.dstIP else { continue }
            let key = "\(src)>\(dst):\(e.dstPort ?? 0)"
            var w = windows[key] ?? []
            w.append((e.effectiveTime, e.id))
            let cutoff = e.effectiveTime.microseconds - window
            w.removeAll { $0.0.microseconds < cutoff }
            windows[key] = w
            if w.count >= threshold, alerted[key].map({ e.effectiveTime.microseconds - $0.microseconds > window }) ?? true {
                alerted[key] = e.effectiveTime
                let client = e.enrichment.srcClientID
                let who = client.map(context.clientName) ?? src.description
                out.append(Finding(ruleName: name, ruleVersion: version, severity: context.isInternal(src) ? .medium : .low,
                                   title: "\(who) was denied \(w.count) times reaching \(dst):\(e.dstPort ?? 0)",
                                   summary: "Rule \(e.ruleName ?? "?") denied \(w.count) connections from \(src) to \(dst):\(e.dstPort ?? 0) within \(Int(context.param("window", self))) s.",
                                   explanation: "**Why:** \(w.count) denied/rejected firewall events for the same source, destination and port occurred inside the \(Int(context.param("window", self)))-second window (threshold \(threshold)). Persistent retries suggest a misconfigured client, a blocked service the user needs, or an external host probing.\n\n**Rule:** `\(e.ruleName ?? "unknown")` on interface \(e.inInterface ?? "?").",
                                   occurredAt: e.effectiveTime, clientID: client, entity: .init(kind: "ip", id: src.description, label: who),
                                   evidence: ["source": src.description, "destination": dst.description, "port": "\(e.dstPort ?? 0)", "protocol": e.protocolNumber.map { IPProtocol.name($0) } ?? "", "count": "\(w.count)", "rule": e.ruleName ?? ""],
                                   baseline: Finding.Baseline(kind: "threshold", value: Double(threshold), unit: "events", period: "\(Int(context.param("window", self))) s", samples: w.count),
                                   eventIDs: w.map(\.1).suffix(100).map { $0 }, steps: ["Decide whether the rule should allow this traffic or the client should stop trying.", "If external: consider whether the source is scanning (see port-scan alerts)."],
                                   dedupeKey: "\(name):\(key)"))
            }
        }
        return out
    }
}

/// A single outbound flow (or aggregate) larger than a fixed size.
public struct LargeOutboundTransferRule: DetectionRule {
    public let name = "large-outbound-transfer"
    public let version = 1
    public let title = "Large outbound transfer"
    public let description = "An internal client sent more than a fixed amount of data to one external destination in a short time."
    public let defaultSeverity = AlertSeverity.medium
    public let parameters = [RuleParameter(key: "bytes", label: "Threshold", value: 1_000_000_000, unit: "bytes", help: "Outbound bytes to one destination that trigger an alert (sampling-corrected)."),
                             RuleParameter(key: "window", label: "Window", value: 3600, unit: "seconds", help: "Accumulation window per client and destination.")]
    private var totals: [String: (bytes: UInt64, since: Timestamp, flows: [Int64])] = [:]
    private var alerted: Set<String> = []
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        var out: [Finding] = []
        let threshold = UInt64(context.param("bytes", self)), window = Int64(context.param("window", self) * 1_000_000)
        for f in flows where f.enrichment.direction == .outbound {
            guard let client = f.enrichment.srcClientID else { continue }
            let key = "\(client)>\(f.dstIP)"
            let corrected = f.octets * UInt64(f.samplingInterval ?? 1)
            var t = totals[key] ?? (0, f.endTime, [])
            if f.endTime.microseconds - t.since.microseconds > window { t = (0, f.endTime, []); alerted.remove(key) }
            t.bytes += corrected; t.flows.append(f.id)
            totals[key] = t
            if t.bytes >= threshold, !alerted.contains(key) {
                alerted.insert(key)
                if context.expected("client", "\(client)", "destination", f.dstIP.description) { continue }
                let cname = context.clientName(client)
                out.append(Finding(ruleName: name, ruleVersion: version, severity: defaultSeverity,
                                   title: "\(cname) sent \(Fmt.bytes(t.bytes)) to \(f.dstIP)",
                                   summary: "\(cname) transferred \(Fmt.bytes(t.bytes)) to \(f.dstIP)\(f.enrichment.dstOrganization.map { " (\($0))" } ?? "") within \(Int(context.param("window", self)) / 60) minutes.",
                                   explanation: "**Why:** the outbound volume to a single destination exceeded the fixed threshold of \(Fmt.bytes(threshold)). Volumes are corrected for the exporter's sampling rate (1:\(f.samplingInterval ?? 1)), so the true amount may differ by the sampling error.\n\n**Destination:** \(f.dstIP):\(f.dstPort) \(f.protocolName)\(f.enrichment.dstCountry.map { ", \($0)" } ?? "")\(f.enrichment.dstASN.map { ", AS\($0)" } ?? "").",
                                   occurredAt: f.endTime, clientID: client, entity: .init(kind: "ip", id: f.dstIP.description, label: f.dstIP.description),
                                   evidence: ["destination": f.dstIP.description, "bytes": "\(t.bytes)", "flows": "\(t.flows.count)", "sampling": "\(f.samplingInterval ?? 1)", "port": "\(f.dstPort)"],
                                   baseline: Finding.Baseline(kind: "threshold", value: Double(threshold), unit: "bytes", period: "\(Int(context.param("window", self))) s", samples: t.flows.count),
                                   flowIDs: Array(t.flows.suffix(200)), steps: ["Confirm the transfer is expected (backup, cloud sync, upload).", "Check the destination's organization and country; mark it expected for this client if legitimate."],
                                   dedupeKey: "\(name):\(key):\(t.since.seconds / 3600)"))
            }
        }
        return out
    }
}

/// Outbound volume in the current hour compared with the client's own trailing baseline.
public struct UnusualVolumeRule: DetectionRule {
    public let name = "unusual-outbound-volume"
    public let version = 1
    public let title = "Unusual outbound volume"
    public let description = "A client's outbound bytes this hour are far above its own typical hourly volume."
    public let defaultSeverity = AlertSeverity.medium
    public let parameters = [RuleParameter(key: "multiplier", label: "Multiplier", value: 8, unit: "× baseline", help: "Alert when the current hour exceeds the median hourly volume by this factor."),
                             RuleParameter(key: "baselineDays", label: "Baseline window", value: 7, unit: "days", help: "Trailing days used for the baseline."),
                             RuleParameter(key: "minBytes", label: "Minimum bytes", value: 200_000_000, unit: "bytes", help: "Never alert below this absolute volume."),
                             RuleParameter(key: "minSamples", label: "Minimum samples", value: 24, unit: "hours", help: "Baseline hours required before the rule can fire.")]
    private var hourTotals: [Int64: (hour: Int64, bytes: UInt64, flows: [Int64])] = [:]
    private var alerted: Set<String> = []
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        var out: [Finding] = []
        let mult = context.param("multiplier", self), days = Int(context.param("baselineDays", self)), minBytes = UInt64(context.param("minBytes", self)), minSamples = Int(context.param("minSamples", self))
        for f in flows where f.enrichment.direction == .outbound {
            guard let client = f.enrichment.srcClientID else { continue }
            let hour = f.endTime.microseconds / 3_600_000_000
            var t = hourTotals[client] ?? (hour, 0, [])
            if t.hour != hour { t = (hour, 0, []) }
            t.bytes += f.octets * UInt64(f.samplingInterval ?? 1); t.flows.append(f.id)
            hourTotals[client] = t
            let key = "\(client):\(hour)"
            guard t.bytes >= minBytes, !alerted.contains(key) else { continue }
            let history = try state.hourlyOutboundBytes(clientID: client, hours: days * 24, before: Timestamp(microseconds: hour * 3_600_000_000))
            guard history.count >= minSamples else { continue }
            let sorted = history.sorted()
            let median = Double(sorted[sorted.count / 2])
            let p95 = Double(sorted[min(sorted.count - 1, Int(Double(sorted.count) * 0.95))])
            let base = max(median, 1)
            guard Double(t.bytes) >= base * mult, Double(t.bytes) > p95 else { continue }
            alerted.insert(key)
            let cname = context.clientName(client)
            out.append(Finding(ruleName: name, ruleVersion: version, severity: defaultSeverity,
                               title: "\(cname) sent \(Fmt.ratio(Double(t.bytes), base)) its usual hourly volume",
                               summary: "\(cname) has sent \(Fmt.bytes(t.bytes)) this hour; its median hour over the last \(days) days is \(Fmt.bytes(Int64(median))).",
                               explanation: "**Why:** the current hour's outbound volume (\(Fmt.bytes(t.bytes))) is \(Fmt.ratio(Double(t.bytes), base)) the client's median hourly outbound volume (\(Fmt.bytes(Int64(median))), \(history.count) hours of history) and above its 95th percentile (\(Fmt.bytes(Int64(p95)))). Threshold multiplier: \(mult)×.",
                               occurredAt: f.endTime, clientID: client, entity: .init(kind: "client", id: "\(client)", label: cname),
                               evidence: ["bytes_this_hour": "\(t.bytes)", "median_hour": "\(Int64(median))", "p95_hour": "\(Int64(p95))", "history_hours": "\(history.count)"],
                               baseline: Finding.Baseline(kind: "rolling", value: median, unit: "bytes/hour", period: "\(days) days", samples: history.count),
                               flowIDs: Array(t.flows.suffix(200)), steps: ["Open the client's top destinations for this hour to see where the volume went.", "Compare with the large-outbound-transfer and first-seen alerts for the same client."],
                               dedupeKey: "\(name):\(key)"))
        }
        return out
    }
}

/// Activity at an hour of day when the client is normally silent.
public struct UnusualTimeRule: DetectionRule {
    public let name = "unusual-activity-time"
    public let version = 1
    public let title = "Unusual activity time"
    public let description = "A client generated outbound traffic during an hour of the day in which it is normally inactive."
    public let defaultSeverity = AlertSeverity.low
    public let parameters = [RuleParameter(key: "baselineDays", label: "Baseline window", value: 14, unit: "days", help: "Trailing days used for the hour-of-day profile."),
                             RuleParameter(key: "minFlows", label: "Minimum flows", value: 20, unit: "flows", help: "Flows in the unusual hour before alerting."),
                             RuleParameter(key: "quietRatio", label: "Quiet ratio", value: 0.02, unit: "fraction", help: "An hour is 'quiet' when it holds less than this fraction of the client's daily activity.")]
    private var hourCounts: [Int64: (hour: Int64, flows: [Int64])] = [:]
    private var alerted: Set<String> = []
    public init() {}

    public mutating func evaluate(flows: [FlowRecord], events: [SyslogEvent], context: DetectionContext, state: any RuleStateStore) throws -> [Finding] {
        var out: [Finding] = []
        let days = Int(context.param("baselineDays", self)), minFlows = Int(context.param("minFlows", self)), quiet = context.param("quietRatio", self)
        for f in flows where f.enrichment.direction == .outbound {
            guard let client = f.enrichment.srcClientID else { continue }
            let hour = f.endTime.microseconds / 3_600_000_000
            var c = hourCounts[client] ?? (hour, [])
            if c.hour != hour { c = (hour, []) }
            c.flows.append(f.id); hourCounts[client] = c
            let key = "\(client):\(hour)"
            guard c.flows.count >= minFlows, !alerted.contains(key) else { continue }
            let hist = try state.hourOfDayHistogram(clientID: client, days: days, before: Timestamp(microseconds: hour * 3_600_000_000))
            let total = hist.reduce(0, +)
            guard hist.count == 24, total >= Int64(minFlows * 24) else { continue }
            var cal = Calendar(identifier: .gregorian); cal.timeZone = .current
            let hod = cal.component(.hour, from: f.endTime.date)
            let share = Double(hist[hod]) / Double(total)
            guard share < quiet else { continue }
            alerted.insert(key)
            let cname = context.clientName(client)
            out.append(Finding(ruleName: name, ruleVersion: version, severity: defaultSeverity,
                               title: "\(cname) is active at an unusual hour (\(hod):00)",
                               summary: "\(cname) produced \(c.flows.count) outbound flows around \(hod):00, an hour that held \(String(format: "%.1f", share * 100)) % of its activity over the last \(days) days.",
                               explanation: "**Why:** over the trailing \(days) days this client's traffic at \(hod):00–\(hod):59 local time was \(hist[hod]) of \(total) flows (\(String(format: "%.2f", share * 100)) %), below the quiet threshold of \(String(format: "%.0f", quiet * 100)) %. \(c.flows.count) flows in this hour exceed the minimum of \(minFlows).",
                               occurredAt: f.endTime, clientID: client, entity: .init(kind: "client", id: "\(client)", label: cname),
                               evidence: ["hour": "\(hod)", "flows_now": "\(c.flows.count)", "share_baseline": String(format: "%.4f", share), "baseline_flows": "\(total)"],
                               baseline: Finding.Baseline(kind: "rolling", value: share, unit: "share of daily flows", period: "\(days) days", samples: Int(total)),
                               flowIDs: Array(c.flows.suffix(100)), steps: ["Check what the client was doing (scheduled backup, update, or someone using it).", "If this schedule is normal, mark the behavior as expected."],
                               dedupeKey: "\(name):\(key)"))
        }
        return out
    }
}
