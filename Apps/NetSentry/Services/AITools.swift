import Foundation
import NetSentryAnalytics
import NetSentryCore
import NetSentryDetection

/// Executes the tools the AI assistant is allowed to call. Every tool reads the same telemetry the
/// dashboard shows — flows and events from the read engine, plus clients and alerts from the
/// collector — so the model's answers are grounded in the data actually captured on this network.
@MainActor
final class AIToolRunner {
    private let model: AppModel
    private let analytics: AnalyticsService
    private var security: SecurityClient { SecurityClient(client: model.client) }

    init(model: AppModel, analytics: AnalyticsService) {
        self.model = model
        self.analytics = analytics
    }

    /// The tool catalog advertised to the provider.
    static var tools: [AITool] { [
        AITool(
            name: "get_network_overview",
            description: "High-level snapshot of the network over a recent window: total flows/bytes, inbound vs outbound split, top talking clients, top external destinations, top destination ports, and event counts. Start here for broad questions about how the network is behaving.",
            parameters: schema(props: [
                "minutes": intProp("Length of the window ending now, in minutes. Default 60.", min: 1, max: 43200)
            ])
        ),
        AITool(
            name: "query_flows",
            description: "List individual network flows (NetFlow/IPFIX records) matching filters, newest or heaviest first. Use this to investigate a specific host, port, or conversation — e.g. what a client has been talking to. Each flow is one src↔dst conversation with byte/packet counts.",
            parameters: schema(props: [
                "minutes": intProp("Window ending now, in minutes. Default 60.", min: 1, max: 43200),
                "ip": strProp("Match flows where this IPv4/IPv6 address is either source or destination."),
                "src_ip": strProp("Match flows with this source IP."),
                "dst_ip": strProp("Match flows with this destination IP."),
                "client_id": intProp("Match flows for this NetSentry client id (source or destination). Use list_clients to resolve names to ids.", min: 0, max: nil),
                "dst_port": intProp("Match flows to this destination port.", min: 0, max: 65535),
                "protocol": intProp("IP protocol number (6=TCP, 17=UDP, 1=ICMP).", min: 0, max: 255),
                "direction": strProp("One of: outbound, inbound, lan, transit."),
                "min_bytes": intProp("Only flows carrying at least this many bytes.", min: 0, max: nil),
                "sort": enumProp("Sort key. 'bytes' (default, heaviest first) or 'recent' (newest first).", ["bytes", "recent"]),
                "limit": intProp("Max flows to return. Default 40, max 150.", min: 1, max: 150),
            ])
        ),
        AITool(
            name: "top_talkers",
            description: "Aggregate flows over a window and rank by a dimension: which destinations, ports, countries, ASNs, services, or clients moved the most traffic. Best for 'who/what is using the most bandwidth' style questions.",
            parameters: schema(props: [
                "dimension": enumProp("What to group by.", ["dst_ip", "src_ip", "dst_port", "protocol", "dst_country", "dst_asn", "dst_org", "service", "direction", "src_client_id", "dst_client_id", "exporter_addr"]),
                "minutes": intProp("Window ending now, in minutes. Default 60.", min: 1, max: 43200),
                "limit": intProp("How many rows to return. Default 15, max 50.", min: 1, max: 50),
            ], required: ["dimension"])
        ),
        AITool(
            name: "list_clients",
            description: "List known devices/clients on the network with their ids, names, IP addresses, MAC, VLAN, hostname, and trusted flag. Use to map an IP or name to a client id, or to enumerate devices.",
            parameters: schema(props: [:])
        ),
        AITool(
            name: "list_alerts",
            description: "List security alerts the detection engine has raised (anomalies, first-seen destinations, policy violations, etc.), newest first. Use when the user asks whether anything is wrong or suspicious.",
            parameters: schema(props: [
                "state": enumProp("Filter by alert state. Default: open alerts only.", ["open", "acknowledged", "resolved", "all"]),
                "client_id": intProp("Only alerts for this client id.", min: 0, max: nil),
                "limit": intProp("Max alerts to return. Default 25, max 100.", min: 1, max: 100),
            ])
        ),
        AITool(
            name: "bandwidth_time_series",
            description: "Bandwidth and flow counts bucketed over time for a window, to spot spikes, trends, or gaps. Returns per-bucket bytes (in/out) and flow counts.",
            parameters: schema(props: [
                "minutes": intProp("Window ending now, in minutes. Default 60.", min: 5, max: 43200),
                "buckets": intProp("Approximate number of time buckets. Default 12, max 60.", min: 2, max: 60),
            ])
        ),
    ] }

    // MARK: - Dispatch

    /// Runs a tool by name and returns a compact JSON/text string for the model.
    func run(name: String, argumentsJSON: String) async -> String {
        let args = (try? JSONSerialization.jsonObject(with: Data(argumentsJSON.utf8))) as? [String: Any] ?? [:]
        analytics.ensureOpen(root: URL(fileURLWithPath: model.storageRootPath))
        do {
            switch name {
            case "get_network_overview": return try await getOverview(args)
            case "query_flows": return try await queryFlows(args)
            case "top_talkers": return try await topTalkers(args)
            case "list_clients": return try await listClients()
            case "list_alerts": return try await listAlerts(args)
            case "bandwidth_time_series": return try await timeSeries(args)
            default: return errorJSON("Unknown tool \"\(name)\".")
            }
        } catch {
            return errorJSON(error.localizedDescription)
        }
    }

    // MARK: - Tools

    private func getOverview(_ args: [String: Any]) async throws -> String {
        let minutes = intArg(args, "minutes", default: 60)
        let range = TimeRange.last(.seconds(minutes * 60))
        var mutable = RecordFilter(range: range)
        mutable.origin = .live
        let filter = mutable

        let totals = try await analytics.run { try await $0.totals(range) }
        let topClients = try await analytics.run { try await $0.topN(TopNQuery(filter: filter, dimension: .srcClient, limit: 5)) } ?? []
        let topDsts = try await analytics.run { try await $0.topN(TopNQuery(filter: filter, dimension: .dstIP, limit: 5)) } ?? []
        let topPorts = try await analytics.run { try await $0.topN(TopNQuery(filter: filter, dimension: .dstPort, limit: 5)) } ?? []
        let eventsByType = try await analytics.run { try await $0.eventCounts(filter, by: "event_type") } ?? []

        var out: [String: Any] = [
            "window_minutes": minutes,
            "collector_connected": model.connectionState == .connected,
            "demo_workspace": model.health?.demoWorkspace ?? model.configuration.demoWorkspace,
        ]
        if let t = totals {
            out["totals"] = [
                "flows": t.flows, "bytes": t.bytes, "bytes_human": Format.bytes(t.bytes),
                "inbound_bytes": t.inboundBytes, "inbound_human": Format.bytes(t.inboundBytes),
                "outbound_bytes": t.outboundBytes, "outbound_human": Format.bytes(t.outboundBytes),
                "packets": t.packets,
            ]
        }
        out["top_clients"] = topClients.map { topNDict($0, resolveClient: true) }
        out["top_destinations"] = topDsts.map { topNDict($0) }
        out["top_ports"] = topPorts.map { topNDict($0) }
        out["events_by_type"] = eventsByType.map { ["type": eventTypeLabel($0.key), "count": $0.count] }
        return json(out)
    }

    private func queryFlows(_ args: [String: Any]) async throws -> String {
        let minutes = intArg(args, "minutes", default: 60)
        var filter = RecordFilter(range: .last(.seconds(minutes * 60)))
        filter.origin = .live
        if let s = strArg(args, "ip"), let ip = IPAddress(s) { filter.anyIP = ip }
        if let s = strArg(args, "src_ip"), let ip = IPAddress(s) { filter.srcIP = ip }
        if let s = strArg(args, "dst_ip"), let ip = IPAddress(s) { filter.dstIP = ip }
        if let c = intArgOptional(args, "client_id") { filter.clientID = Int64(c) }
        if let p = intArgOptional(args, "dst_port") { filter.ports = [UInt16(truncatingIfNeeded: p)] }
        if let p = intArgOptional(args, "protocol") { filter.protocols = [UInt8(truncatingIfNeeded: p)] }
        if let d = strArg(args, "direction"), let dir = direction(from: d) { filter.directions = [dir] }
        if let m = intArgOptional(args, "min_bytes") { filter.minOctets = UInt64(max(0, m)) }

        var mutable = FlowQuery(filter: filter)
        mutable.limit = min(max(intArg(args, "limit", default: 40), 1), 150)
        if strArg(args, "sort") == "recent" {
            mutable.sort = .startTime; mutable.direction = .descending
        } else {
            mutable.sort = .octets; mutable.direction = .descending
        }
        let q = mutable

        let page = try await analytics.run { try await $0.flows(q) }
        guard let page else { return errorJSON("The telemetry store isn't open yet — no flows are available.") }
        let rows = page.rows.map { flowDict($0) }
        return json([
            "window_minutes": minutes,
            "returned": rows.count,
            "segments_scanned": page.segmentsScanned,
            "flows": rows,
        ])
    }

    private func topTalkers(_ args: [String: Any]) async throws -> String {
        guard let dimRaw = strArg(args, "dimension"), let dim = GroupDimension(rawValue: dimRaw) else {
            return errorJSON("Missing or invalid 'dimension'.")
        }
        let minutes = intArg(args, "minutes", default: 60)
        var mutable = RecordFilter(range: .last(.seconds(minutes * 60)))
        mutable.origin = .live
        let filter = mutable
        let limit = min(max(intArg(args, "limit", default: 15), 1), 50)
        let rows = try await analytics.run { try await $0.topN(TopNQuery(filter: filter, dimension: dim, limit: limit)) } ?? []
        let resolve = dim == .srcClient || dim == .dstClient
        return json([
            "dimension": dimRaw,
            "window_minutes": minutes,
            "rows": rows.map { topNDict($0, resolveClient: resolve) },
        ])
    }

    private func listClients() async throws -> String {
        let clients = try await security.clients()
        let rows = clients.prefix(200).map { c -> [String: Any] in
            [
                "id": c.id, "label": c.label, "hostname": c.hostname ?? "",
                "addresses": c.addresses, "mac": c.primaryMAC ?? "",
                "vlan": c.vlanID.map { "\($0)" } ?? "", "trusted": c.trusted,
                "tags": c.tags, "last_seen": Format.time(c.lastSeen),
            ]
        }
        return json(["count": clients.count, "clients": Array(rows)])
    }

    private func listAlerts(_ args: [String: Any]) async throws -> String {
        let stateArg = strArg(args, "state") ?? "open"
        let states: [AlertState]?
        switch stateArg {
        case "open": states = [.open]
        case "acknowledged": states = [.acknowledged]
        case "resolved": states = [.resolved]
        default: states = nil // "all"
        }
        let clientID = intArgOptional(args, "client_id").map { Int64($0) }
        let limit = min(max(intArg(args, "limit", default: 25), 1), 100)
        let alerts = try await security.alerts(states: states, clientID: clientID)
        let rows = alerts.prefix(limit).map { a -> [String: Any] in
            [
                "id": a.id, "severity": "\(a.severity)", "state": a.state.rawValue,
                "rule": a.ruleName, "title": a.title, "summary": a.summary,
                "client_id": a.clientID.map { "\($0)" } ?? "",
                "occurrences": a.occurrenceCount,
                "first": Format.time(a.firstOccurrence), "last": Format.time(a.lastOccurrence),
            ]
        }
        return json(["count": alerts.count, "returned": rows.count, "alerts": Array(rows)])
    }

    private func timeSeries(_ args: [String: Any]) async throws -> String {
        let minutes = intArg(args, "minutes", default: 60)
        let buckets = min(max(intArg(args, "buckets", default: 12), 2), 60)
        let range = TimeRange.last(.seconds(minutes * 60))
        let bucketSeconds = max(60, (minutes * 60) / buckets)
        var mutable = RecordFilter(range: range)
        mutable.origin = .live
        let filter = mutable
        let series = try await analytics.run { try await $0.timeSeries(filter, bucket: .seconds(bucketSeconds)) } ?? []
        let rows = series.map { b -> [String: Any] in
            [
                "time": Format.time(b.bucket), "flows": b.flows, "bytes": b.bytes,
                "inbound_bytes": b.inboundBytes, "outbound_bytes": b.outboundBytes,
            ]
        }
        return json(["window_minutes": minutes, "bucket_seconds": bucketSeconds, "series": rows])
    }

    // MARK: - Row shaping

    private func flowDict(_ f: FlowRecord) -> [String: Any] {
        var d: [String: Any] = [
            "start": Format.time(f.startTime),
            "src": "\(f.srcIP):\(f.srcPort)",
            "dst": "\(f.dstIP):\(f.dstPort)",
            "protocol": f.protocolName,
            "direction": f.enrichment.direction.label,
            "bytes": Int64(clamping: f.octets), "bytes_human": Format.bytes(f.octets),
            "packets": Int64(clamping: f.packets),
        ]
        if let s = f.enrichment.service { d["service"] = s }
        if let c = f.enrichment.dstCountry { d["dst_country"] = c }
        if let a = f.enrichment.dstASN { d["dst_asn"] = a }
        if let o = f.enrichment.dstOrganization { d["dst_org"] = o }
        if let c = f.enrichment.srcClientID { d["src_client_id"] = c }
        if let c = f.enrichment.dstClientID { d["dst_client_id"] = c }
        return d
    }

    private func topNDict(_ r: TopNRow, resolveClient: Bool = false) -> [String: Any] {
        var key: Any = r.key
        if resolveClient, let id = Int64(r.key) { key = "client \(id)" }
        return ["key": key, "flows": r.flows, "bytes": r.bytes, "bytes_human": Format.bytes(r.bytes), "packets": r.packets]
    }

    private func eventTypeLabel(_ raw: String) -> String {
        guard let n = UInt8(raw), let t = EventType(rawValue: n) else { return raw }
        return t.label
    }

    private func direction(from s: String) -> TrafficDirection? {
        switch s.lowercased() {
        case "outbound": .outbound
        case "inbound": .inbound
        case "lan", "internal": .lan
        case "transit": .transit
        default: nil
        }
    }

    // MARK: - Argument helpers

    private func intArg(_ args: [String: Any], _ key: String, default def: Int) -> Int { intArgOptional(args, key) ?? def }
    private func intArgOptional(_ args: [String: Any], _ key: String) -> Int? {
        if let n = args[key] as? Int { return n }
        if let d = args[key] as? Double { return Int(d) }
        if let s = args[key] as? String, let n = Int(s) { return n }
        return nil
    }
    private func strArg(_ args: [String: Any], _ key: String) -> String? {
        guard let s = args[key] as? String else { return nil }
        let t = s.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? nil : t
    }

    // MARK: - JSON

    private func json(_ obj: Any) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes]),
              let s = String(data: data, encoding: .utf8) else { return "{}" }
        return s
    }
    private func errorJSON(_ message: String) -> String { json(["error": message]) }

    // MARK: - Schema builders

    private static func schema(props: [String: [String: Any]], required: [String] = []) -> [String: Any] {
        var s: [String: Any] = ["type": "object", "properties": props]
        s["required"] = required
        return s
    }
    private static func intProp(_ desc: String, min: Int?, max: Int?) -> [String: Any] {
        var p: [String: Any] = ["type": "integer", "description": desc]
        if let min { p["minimum"] = min }
        if let max { p["maximum"] = max }
        return p
    }
    private static func strProp(_ desc: String) -> [String: Any] { ["type": "string", "description": desc] }
    private static func enumProp(_ desc: String, _ values: [String]) -> [String: Any] { ["type": "string", "description": desc, "enum": values] }
}
