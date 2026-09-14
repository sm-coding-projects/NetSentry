import Foundation
import NetSentryAnalytics
import NetSentryCore
import NetSentryPersistence

/// One entry of a unified investigation timeline. Relations are stated as observations
/// (same addresses, same client, temporal proximity), never as causes.
public struct TimelineEntry: Sendable, Hashable, Identifiable {
    public enum Kind: String, Sendable, Codable, CaseIterable { case flow, firewall, ids, auth, vpn, dhcp, dns, system, otherEvent, alert, annotation, gap }
    public var id: String
    public var time: Timestamp
    public var endTime: Timestamp?
    public var kind: Kind
    public var title: String
    public var detail: String
    public var relations: [String]      // e.g. "same client", "same destination", "within 3 s of anchor"
    public var flow: FlowRecord?
    public var event: SyslogEvent?
    public var alertID: Int64?
    public var gap: CollectionGap?
    public var isAnchor: Bool
}

/// What the investigation is centered on.
public enum InvestigationAnchor: Sendable, Hashable, Codable {
    case flow(FlowRecord)
    case event(SyslogEvent)
    case client(Int64, label: String, addresses: [String])
    case address(IPAddress)
    case alert(id: Int64, title: String, time: Timestamp, clientID: Int64?, addresses: [String], flowIDs: [Int64], eventIDs: [Int64])
    case timeRange

    public var time: Timestamp? {
        switch self {
        case .flow(let f): f.startTime
        case .event(let e): e.effectiveTime
        case .alert(_, _, let t, _, _, _, _): t
        default: nil
        }
    }
    public var label: String {
        switch self {
        case .flow(let f): "Flow \(f.srcIP):\(f.srcPort) → \(f.dstIP):\(f.dstPort)"
        case .event(let e): "Event: \(e.message.prefix(60))"
        case .client(_, let l, _): "Client \(l)"
        case .address(let ip): "Address \(ip)"
        case .alert(_, let t, _, _, _, _, _): "Alert: \(t)"
        case .timeRange: "Time range"
        }
    }
}

public struct InvestigationRequest: Sendable, Hashable {
    public var anchor: InvestigationAnchor
    public var range: TimeRange
    public var maxFlows = 2_000
    public var maxEvents = 2_000
    public var origin: Origin = .live
    public init(anchor: InvestigationAnchor, range: TimeRange) { self.anchor = anchor; self.range = range }
}

public struct Investigation: Sendable {
    public var request: InvestigationRequest
    public var entries: [TimelineEntry]
    public var truncated: Bool
    public var elapsed: Duration
}

/// Builds a unified timeline from the store for any anchor.
public actor TimelineBuilder {
    private let engine: ReadEngine
    private let meta: MetaStore
    public init(engine: ReadEngine, meta: MetaStore) { self.engine = engine; self.meta = meta }

    public func build(_ req: InvestigationRequest) async throws -> Investigation {
        let t0 = ContinuousClock.now
        var filter = RecordFilter(range: req.range); filter.origin = req.origin
        var anchorAddresses = Set<IPAddress>()
        var anchorClient: Int64?
        switch req.anchor {
        case .flow(let f): anchorAddresses = [f.srcIP, f.dstIP]; anchorClient = f.enrichment.srcClientID ?? f.enrichment.dstClientID
        case .event(let e): anchorAddresses = Set([e.srcIP, e.dstIP].compactMap { $0 }); anchorClient = e.enrichment.srcClientID ?? e.enrichment.dstClientID
        case .client(let id, _, let addrs): anchorClient = id; anchorAddresses = Set(addrs.compactMap(IPAddress.init))
        case .address(let ip): anchorAddresses = [ip]
        case .alert(_, _, _, let c, let addrs, _, _): anchorClient = c; anchorAddresses = Set(addrs.compactMap(IPAddress.init))
        case .timeRange: break
        }
        // Scope the record queries: by client when known, else by the anchor address(es); a plain range otherwise.
        if let c = anchorClient { filter.clientID = c } else if let ip = anchorAddresses.first, anchorAddresses.count == 1 { filter.anyIP = ip }
        var entries: [TimelineEntry] = []
        var truncated = false
        // Flows
        var fq = FlowQuery(filter: filter); fq.limit = req.maxFlows; fq.direction = .ascending
        let flows = try await engine.flows(fq)
        if flows.nextCursor != nil { truncated = true }
        var extraFlows: [FlowRecord] = []
        if anchorAddresses.count > 1 {   // include flows for the other anchor address too
            for ip in anchorAddresses.dropFirst() { var f2 = filter; f2.clientID = nil; f2.anyIP = ip; var q = FlowQuery(filter: f2); q.limit = req.maxFlows / 2; q.direction = .ascending; extraFlows += try await engine.flows(q).rows }
        }
        let seenFlow = Set(flows.rows.map(\.id))
        for f in flows.rows + extraFlows.filter({ !seenFlow.contains($0.id) }) {
            entries.append(TimelineEntry(id: "f\(f.id)", time: f.startTime, endTime: f.endTime, kind: .flow,
                                         title: "\(f.srcIP):\(f.srcPort) → \(f.dstIP):\(f.dstPort) \(f.protocolName)",
                                         detail: "\(f.enrichment.direction.label) · \(ByteCountFormatter.string(fromByteCount: Int64(clamping: f.octets), countStyle: .file)) · \(f.packets) pkts\(f.enrichment.service.map { " · \($0)" } ?? "")\(f.enrichment.dstCountry.map { " · \($0)" } ?? "")",
                                         relations: Self.relations(flowSrc: f.srcIP, dst: f.dstIP, client: f.enrichment.srcClientID ?? f.enrichment.dstClientID, time: f.startTime, anchor: req.anchor, anchorAddresses: anchorAddresses, anchorClient: anchorClient),
                                         flow: f, event: nil, alertID: nil, gap: nil, isAnchor: Self.isAnchor(req.anchor, flowID: f.id)))
        }
        // Events
        var eq = EventQuery(filter: filter); eq.limit = req.maxEvents; eq.direction = .ascending
        let events = try await engine.events(eq)
        if events.nextCursor != nil { truncated = true }
        for e in events.rows {
            let kind: TimelineEntry.Kind = switch e.eventType { case .firewall: .firewall; case .ids: .ids; case .auth: .auth; case .vpn: .vpn; case .dhcp: .dhcp; case .dns: .dns; case .system: .system; default: .otherEvent }
            entries.append(TimelineEntry(id: "e\(e.id)", time: e.effectiveTime, endTime: nil, kind: kind,
                                         title: [e.action?.label, e.ruleName ?? e.idsSignature, e.username.map { "user \($0)" }].compactMap { $0 }.joined(separator: " · ").isEmpty ? e.eventType.label : [e.action?.label, e.ruleName ?? e.idsSignature, e.username.map { "user \($0)" }].compactMap { $0 }.joined(separator: " · "),
                                         detail: "\(e.srcIP.map { "\($0)\(e.srcPort.map { ":\($0)" } ?? "")" } ?? "")\(e.dstIP.map { " → \($0)\(e.dstPort.map { ":\($0)" } ?? "")" } ?? "") · \(e.message.prefix(120))",
                                         relations: Self.relations(flowSrc: e.srcIP, dst: e.dstIP, client: e.enrichment.srcClientID ?? e.enrichment.dstClientID, time: e.effectiveTime, anchor: req.anchor, anchorAddresses: anchorAddresses, anchorClient: anchorClient),
                                         flow: nil, event: e, alertID: nil, gap: nil, isAnchor: Self.isAnchor(req.anchor, eventID: e.id)))
        }
        // Alerts, annotations, gaps from SQLite
        let alertParams: [any SQLBindable] = [req.range.start, req.range.end]
        for r in try meta.db.query("SELECT id, title, severity, first_occurrence, last_occurrence, client_id, entity_json FROM alerts WHERE last_occurrence >= ? AND first_occurrence <= ? ORDER BY first_occurrence", alertParams) {
            let cid = r.int64("client_id")
            let related = anchorClient != nil && cid == anchorClient || (r.string("entity_json") ?? "").contains(anchorAddresses.first?.description ?? "\u{0}") || { if case .alert(let id, _, _, _, _, _, _) = req.anchor { return id == r.int64("id") }; return false }()
            guard related || anchorClient == nil && anchorAddresses.isEmpty else { continue }
            entries.append(TimelineEntry(id: "a\(r.int64("id") ?? 0)", time: r.timestamp("first_occurrence") ?? .now, endTime: r.timestamp("last_occurrence"), kind: .alert,
                                         title: r.string("title") ?? "Alert", detail: "severity \(AlertSeverity(rawValue: UInt8(r.int("severity") ?? 0))?.label ?? "")",
                                         relations: cid != nil && cid == anchorClient ? ["same client"] : [], flow: nil, event: nil, alertID: r.int64("id"), gap: nil,
                                         isAnchor: { if case .alert(let id, _, _, _, _, _, _) = req.anchor { return id == r.int64("id") }; return false }()))
        }
        for r in try meta.db.query("SELECT id, ts, ts_end, kind, title, text FROM annotations WHERE ts >= ? AND ts <= ? ORDER BY ts", alertParams) {
            entries.append(TimelineEntry(id: "n\(r.int64("id") ?? 0)", time: r.timestamp("ts") ?? .now, endTime: r.timestamp("ts_end"), kind: .annotation, title: r.string("title") ?? "Note",
                                         detail: r.string("text") ?? "", relations: ["user annotation"], flow: nil, event: nil, alertID: nil, gap: nil, isAnchor: false))
        }
        for g in try await meta.gaps(from: req.range.start, to: req.range.end) {
            entries.append(TimelineEntry(id: "g\(g.id)", time: g.start, endTime: g.end, kind: .gap, title: "Collection gap: \(g.kind.label)", detail: g.reason + " — records in this period may be missing; absence of activity is not evidence.",
                                         relations: [], flow: nil, event: nil, alertID: nil, gap: g, isAnchor: false))
        }
        entries.sort { $0.time < $1.time }
        return Investigation(request: req, entries: entries, truncated: truncated, elapsed: ContinuousClock.now - t0)
    }

    static func isAnchor(_ a: InvestigationAnchor, flowID: Int64? = nil, eventID: Int64? = nil) -> Bool {
        switch a {
        case .flow(let f): return flowID == f.id
        case .event(let e): return eventID == e.id
        case .alert(_, _, _, _, _, let fids, let eids): return (flowID.map { fids.contains($0) } ?? false) || (eventID.map { eids.contains($0) } ?? false)
        default: return false
        }
    }

    static func relations(flowSrc: IPAddress?, dst: IPAddress?, client: Int64?, time: Timestamp, anchor: InvestigationAnchor, anchorAddresses: Set<IPAddress>, anchorClient: Int64?) -> [String] {
        var r: [String] = []
        if let c = client, c == anchorClient { r.append("same client") }
        let addrs = Set([flowSrc, dst].compactMap { $0 })
        let common = addrs.intersection(anchorAddresses)
        if !common.isEmpty { r.append("same address: \(common.map(\.description).sorted().joined(separator: ", "))") }
        if let t = anchor.time {
            let d = abs(time.microseconds - t.microseconds)
            if d <= 5_000_000 { r.append("within \(d / 1_000_000) s of anchor") } else if d <= 60_000_000 { r.append("within a minute of anchor") }
        }
        return r
    }
}
