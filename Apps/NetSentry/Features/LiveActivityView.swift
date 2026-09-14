import SwiftUI
import NetSentryCore
import NetSentryIPC

/// Real-time sampled stream of decoded flows and events. The collector samples to
/// `liveMaxRecordsPerSecond`; the view keeps a bounded ring and shows how much was left out.
struct LiveActivityView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: LiveRow.ID?
    @State private var search = ""
    @State private var kind: Kind = .both

    enum Kind: String, CaseIterable, Identifiable { case both, flows, events; var id: String { rawValue }
        var label: String { switch self { case .both: "Flows + events"; case .flows: "Flows"; case .events: "Events" } } }

    var rows: [LiveRow] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        return model.liveRows.filter { r in
            (kind == .both || (kind == .flows && r.isFlow) || (kind == .events && !r.isFlow)) && (q.isEmpty || r.searchText.contains(q))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 12) {
                    Button { model.livePaused.toggle() } label: { Label(model.livePaused ? "Resume" : "Pause", systemImage: model.livePaused ? "play.fill" : "pause.fill") }
                        .keyboardShortcut(.space, modifiers: [])
                    Picker("Show", selection: $kind) { ForEach(Kind.allCases) { Text($0.label).tag($0) } }.pickerStyle(.segmented).frame(width: 260).labelsHidden()
                    TextField("Filter by address, port, client, rule, text…", text: $search).textFieldStyle(.roundedBorder).frame(width: 300)
                    Text(statusText).font(.caption).foregroundStyle(.secondary)
                    Button("Clear") { model.clearLive() }
                }
                .padding(10)
            }
            Divider()
            HSplitView {
                Table(rows, selection: $selection) {
                    TableColumn("Time") { r in Text(r.time.date.formatted(date: .omitted, time: .standard)).monospacedDigit() }.width(80)
                    TableColumn("Kind") { r in StatusBadge(text: r.kindLabel, kind: r.badge) }.width(90)
                    TableColumn("Direction") { r in Text(r.direction) }.width(70)
                    TableColumn("Source") { r in Text(r.source).monospaced() }
                    TableColumn("Destination") { r in Text(r.destination).monospaced() }
                    TableColumn("Proto") { r in Text(r.proto) }.width(60)
                    TableColumn("Bytes / Detail") { r in Text(r.detail).lineLimit(1) }
                }
                .accessibilityLabel("Live activity table")                .frame(minWidth: 320)
                if let sel = selection, let row = model.liveRows.first(where: { $0.id == sel }) {
                    LiveInspector(row: row).frame(minWidth: 280, idealWidth: 340)
                } else {
                    ContentUnavailableView("Select a record", systemImage: "sidebar.right", description: Text("All decoded fields, including unmapped IPFIX elements and raw syslog text, appear here."))
                        .frame(minWidth: 280, idealWidth: 340)
                }
            }
        }
        .task { await model.subscribeLive() }
        .onDisappear { Task { await model.unsubscribeLive() } }
    }

    private var statusText: String {
        var parts: [String] = ["\(model.liveRows.count) shown"]
        if model.liveSampledOut > 0 { parts.append("\(model.liveSampledOut) not shown (sampled)") }
        if model.livePaused { parts.append("paused · \(model.livePausedDropped) skipped") }
        if model.health?.demoWorkspace == true { parts.append("SIMULATED") }
        return parts.joined(separator: " · ")
    }
}

struct LiveRow: Identifiable, Hashable {
    let id: Int
    let time: Timestamp
    let flow: FlowRecord?
    let event: SyslogEvent?
    var isFlow: Bool { flow != nil }

    var kindLabel: String { flow != nil ? "Flow" : (event?.eventType.label ?? "Event") }
    var badge: StatusBadge.Kind {
        if flow != nil { return .neutral }
        switch event?.action { case .deny, .reject, .block: return .error; case .alert: return .warning; default: return event?.severity ?? .debug <= .warning ? .warning : .ok }
    }
    var direction: String { (flow?.enrichment.direction ?? event?.enrichment.direction ?? .unknown).label }
    var source: String {
        if let f = flow { return "\(f.srcIP):\(f.srcPort)" }
        if let e = event { return e.srcIP.map { "\($0)\(e.srcPort.map { ":\($0)" } ?? "")" } ?? e.hostname ?? e.sourceIP.description }
        return ""
    }
    var destination: String {
        if let f = flow { return "\(f.dstIP):\(f.dstPort)" }
        if let e = event { return e.dstIP.map { "\($0)\(e.dstPort.map { ":\($0)" } ?? "")" } ?? "" }
        return ""
    }
    var proto: String {
        if let f = flow { return f.protocolName }
        return event?.protocolNumber.map { IPProtocol.name($0) } ?? ""
    }
    var detail: String {
        if let f = flow {
            let sampled = f.samplingInterval.map { " · sampled 1:\($0)" } ?? ""
            return "\(Format.bytes(f.octets)) · \(f.packets) pkts · \(Format.duration(f.duration))\(sampled)"
        }
        if let e = event {
            var bits: [String] = []
            if let a = e.action { bits.append(a.label) }
            if let r = e.ruleName { bits.append(r) }
            if let s = e.idsSignature { bits.append(s) }
            if let u = e.username { bits.append("user \(u)") }
            bits.append(e.message)
            return bits.joined(separator: " · ")
        }
        return ""
    }
    var searchText: String { (source + " " + destination + " " + proto + " " + detail + " " + kindLabel + " " + direction).lowercased() }
}

struct LiveInspector: View {
    let row: LiveRow
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text(row.kindLabel).font(.headline)
                if let f = row.flow { fields(FlowFields.describe(f)) }
                if let e = row.event {
                    fields(EventFields.describe(e))
                    GroupBox("Raw message") {
                        Text(e.raw ?? e.message).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .padding(12)
        }
    }
    private func fields(_ items: [(String, String)]) -> some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
            ForEach(items, id: \.0) { k, v in
                GridRow { Text(k).foregroundStyle(.secondary).font(.caption); Text(v).font(.caption.monospaced()).textSelection(.enabled) }
            }
        }
    }
}

enum FlowFields {
    static func describe(_ f: FlowRecord) -> [(String, String)] {
        var out: [(String, String)] = [
            ("Exporter", "\(f.exporter)"), ("Sequence", "\(f.exportSequence)"), ("Received", Format.time(f.receivedAt)), ("Export time", Format.time(f.exportTime)),
            ("Start", Format.time(f.startTime)), ("End", Format.time(f.endTime)), ("Duration", Format.duration(f.duration)),
            ("Source", "\(f.srcIP):\(f.srcPort)"), ("Destination", "\(f.dstIP):\(f.dstPort)"), ("Protocol", "\(f.protocolName) (\(f.protocolNumber))"),
            ("TCP flags", String(format: "0x%02x", f.tcpFlags)), ("Packets", "\(f.packets)"), ("Octets", "\(f.octets)"),
            ("Direction", f.enrichment.direction.label), ("Internal", "\(f.enrichment.srcInternal) → \(f.enrichment.dstInternal)"),
        ]
        if let v = f.reverseOctets { out.append(("Reverse octets", "\(v)")) }
        if let v = f.reversePackets { out.append(("Reverse packets", "\(v)")) }
        if let v = f.ingressInterface { out.append(("Ingress if", "\(v)")) }
        if let v = f.egressInterface { out.append(("Egress if", "\(v)")) }
        if let v = f.srcVLAN { out.append(("Src VLAN", "\(v)")) }
        if let v = f.dstVLAN { out.append(("Dst VLAN", "\(v)")) }
        if let v = f.flowDirection { out.append(("Exporter direction", v == 0 ? "ingress (0)" : "egress (\(v))")) }
        if let v = f.flowEndReason { out.append(("End reason", "\(v)")) }
        if let v = f.samplingInterval { out.append(("Sampling", "1:\(v)")) }
        if let v = f.postNATSrcIP { out.append(("Post-NAT src", "\(v)\(f.postNATSrcPort.map { ":\($0)" } ?? "")")) }
        if let v = f.postNATDstIP { out.append(("Post-NAT dst", "\(v)\(f.postNATDstPort.map { ":\($0)" } ?? "")")) }
        if let v = f.applicationID { out.append(("Application", v)) }
        if let t = f.icmpType { out.append(("ICMP", "\(t)/\(f.icmpCode ?? 0)")) }
        if f.clockSkewMicroseconds != 0 { out.append(("Exporter skew", String(format: "%+.1f s", Double(f.clockSkewMicroseconds) / 1e6))) }
        for e in f.extraElements { out.append(("IE \(e.key)", e.value.map { String(format: "%02x", $0) }.joined())) }
        return out
    }
}

enum EventFields {
    static func describe(_ e: SyslogEvent) -> [(String, String)] {
        var out: [(String, String)] = [
            ("Received", Format.time(e.receivedAt)), ("Event time", e.eventTime.map { Format.time($0) + (e.timeInferred ? " (inferred)" : "") } ?? "—"),
            ("Sender", "\(e.sourceIP) (\(e.transport.label))"), ("Facility", e.facility.label), ("Severity", e.severity.label),
            ("Syslog", e.syslogVersion == 1 ? "RFC 5424" : "RFC 3164 style"), ("Parser", "\(e.parserName) v\(e.parserVersion) · \(e.parseStatus)"), ("Type", e.eventType.label),
        ]
        if let v = e.hostname { out.append(("Host", v)) }
        if let v = e.appName { out.append(("App", v + (e.procID.map { "[\($0)]" } ?? ""))) }
        if let v = e.msgID { out.append(("Msg ID", v)) }
        if let v = e.srcIP { out.append(("Source", "\(v)\(e.srcPort.map { ":\($0)" } ?? "")")) }
        if let v = e.dstIP { out.append(("Destination", "\(v)\(e.dstPort.map { ":\($0)" } ?? "")")) }
        if let v = e.protocolNumber { out.append(("Protocol", IPProtocol.name(v))) }
        if let v = e.action { out.append(("Action", v.label)) }
        if let v = e.inInterface { out.append(("In interface", v)) }
        if let v = e.outInterface { out.append(("Out interface", v)) }
        if let v = e.vlan { out.append(("VLAN", "\(v)")) }
        if let v = e.ruleName { out.append(("Rule", v + (e.ruleID.map { " (#\($0))" } ?? ""))) }
        if let v = e.username { out.append(("User", v)) }
        if let v = e.deviceID { out.append(("Device", v)) }
        if let v = e.idsSignature { out.append(("Signature", "\(v) (\(e.idsSignatureID ?? 0))")) }
        if let v = e.idsCategory { out.append(("Category", v)) }
        if let v = e.idsSeverity { out.append(("IDS severity", "\(v)")) }
        for (k, v) in e.structuredData { out.append(("SD \(k)", v.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " "))) }
        for (k, v) in e.attributes.sorted(by: { $0.key < $1.key }) { out.append((k, v)) }
        return out
    }
}

extension Format {
    static func duration(_ d: Duration) -> String {
        let s = Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
        if s < 1 { return String(format: "%.0f ms", s * 1000) }
        if s < 60 { return String(format: "%.1f s", s) }
        return String(format: "%.1f min", s / 60)
    }
}
