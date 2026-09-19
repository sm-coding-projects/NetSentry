import SwiftUI
import NetSentryExport
import NetSentryAnalytics
import NetSentryCore
import NetSentryIPC
import UniformTypeIdentifiers

/// Historical flow table: typed filters → paged, sortable results from the read engine.
struct FlowsView: View {
    @Environment(AppModel.self) private var model
    @Environment(AnalyticsService.self) private var analytics
    @State private var preset: RangePreset = .h1
    @State private var ipText = ""
    @State private var portText = ""
    @State private var direction: TrafficDirection? = nil
    @State private var proto: Int = 0
    @State private var sort: FlowSortKey = .startTime
    @State private var descending = true
    @State private var page: QueryPage<FlowRecord>?
    @State private var rows: [FlowRecord] = []
    @State private var selection: FlowRecord.ID?
    @State private var loading = false
    @State private var error: String?
    @State private var task: Task<QueryPage<FlowRecord>?, any Error>?
    @State private var savedName = ""
    @State private var showExport = false
    @AppStorage("flows.columns") private var columnSetting = "time,dir,src,dst,proto,bytes,pkts,dur"

    var body: some View {
        VStack(spacing: 0) {
            filterBar
            Divider()
            GeometryReader { geo in
            HSplitView {
                table.frame(minWidth: 320).frame(height: geo.size.height)
                if let id = selection, let f = rows.first(where: { $0.id == id }) {
                    ScrollView { FlowDetail(flow: f).padding(12) }.frame(minWidth: 300, idealWidth: 360).frame(height: geo.size.height)
                } else {
                    ContentUnavailableView("Select a flow", systemImage: "sidebar.right", description: Text("Every decoded field is shown, including unmapped IPFIX elements.")).frame(minWidth: 300, idealWidth: 360).frame(height: geo.size.height)
                }
            }
            .frame(width: geo.size.width, height: geo.size.height)
            }
            statusBar
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task { await load(reset: true) }
        .sheet(isPresented: $showExport) {
            ExportSheet(title: "Export \(rows.count) loaded flows") { format, policy in
                let name = "flows-\(Date.now.formatted(.iso8601.year().month().day()))"
                switch format {
                case .csv: _ = ExportService.save(data: Data(RecordExport.flowsCSV(rows, policy: policy).utf8), suggestedName: name + ".csv", type: .commaSeparatedText)
                case .json: if let d = try? RecordExport.flowsJSON(rows, policy: policy) { _ = ExportService.save(data: d, suggestedName: name + ".json", type: .json) }
                }
            }
        }
        .onChange(of: preset) { _, _ in Task { await load(reset: true) } }
        .onChange(of: sort) { _, _ in Task { await load(reset: true) } }
        .onChange(of: descending) { _, _ in Task { await load(reset: true) } }
    }

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
        HStack(spacing: 10) {
            Picker("Range", selection: $preset) { ForEach(RangePreset.allCases) { Text($0.rawValue).tag($0) } }.frame(width: 120).labelsHidden()
            TextField("IP or CIDR", text: $ipText).textFieldStyle(.roundedBorder).frame(width: 170).onSubmit { Task { await load(reset: true) } }
            TextField("Port", text: $portText).textFieldStyle(.roundedBorder).frame(width: 70).onSubmit { Task { await load(reset: true) } }
            Picker("Protocol", selection: $proto) { Text("Any").tag(0); Text("TCP").tag(6); Text("UDP").tag(17); Text("ICMP").tag(1) }.frame(width: 90).labelsHidden()
            Picker("Direction", selection: $direction) {
                Text("Any direction").tag(TrafficDirection?.none)
                ForEach([TrafficDirection.outbound, .inbound, .lan, .transit], id: \.self) { Text($0.label).tag(TrafficDirection?.some($0)) }
            }.frame(width: 140).labelsHidden()
            Picker("Sort", selection: $sort) {
                Text("Start time").tag(FlowSortKey.startTime); Text("Bytes").tag(FlowSortKey.octets); Text("Packets").tag(FlowSortKey.packets); Text("Duration").tag(FlowSortKey.duration); Text("Port").tag(FlowSortKey.dstPort)
            }.frame(width: 120).labelsHidden()
            Toggle("Desc", isOn: $descending).toggleStyle(.checkbox)
            Button("Export…") { showExport = true }.disabled(rows.isEmpty).keyboardShortcut("e", modifiers: .command)
            Button("Search") { Task { await load(reset: true) } }.keyboardShortcut(.return, modifiers: .command)
            Menu("Columns") {
                ForEach(FlowColumn.allCases) { c in
                    Toggle(c.title, isOn: Binding(get: { columns.contains(c) }, set: { on in var set = columns; if on { set.insert(c) } else { set.remove(c) }; columnSetting = FlowColumn.allCases.filter { set.contains($0) }.map(\.rawValue).joined(separator: ",") } ))
                }
            }.frame(width: 100)
            Button("Export CSV…") { exportCSV() }.disabled(rows.isEmpty)
            SavedSearchMenu(view: "flows") { apply($0) }
        }
        .padding(10)
        }
    }

    private func apply(_ f: RecordFilter) {
        ipText = f.anyIP?.description ?? f.prefix?.description ?? f.srcIP?.description ?? f.dstIP?.description ?? ""
        portText = f.ports.first.map(String.init) ?? ""
        proto = Int(f.protocols.first ?? 0)
        direction = f.directions.first
        if let p = RangePreset.allCases.first(where: { abs($0.duration.microsecondsValue - f.range.duration.microsecondsValue) < 60_000_000 }) { preset = p }
        Task { await load(reset: true) }
    }

    private var columns: Set<FlowColumn> { Set(columnSetting.split(separator: ",").compactMap { FlowColumn(rawValue: String($0)) }) }

    private var table: some View {
        Table(rows, selection: $selection) {
            TableColumn("Time") { f in Text(f.startTime.date.formatted(date: .abbreviated, time: .standard)).monospacedDigit() }.width(min: 150, ideal: 170)
            TableColumn("Dir") { f in Text(f.enrichment.direction.label) }.width(70)
            TableColumn("Source") { f in Text("\(f.srcIP):\(f.srcPort)").monospaced() }
            TableColumn("Destination") { f in Text("\(f.dstIP):\(f.dstPort)").monospaced() }
            TableColumn("Proto") { f in Text(f.protocolName) }.width(60)
            TableColumn("Bytes") { f in Text(Format.bytes(f.octets)).monospacedDigit() }.width(80)
            TableColumn("Packets") { f in Text("\(f.packets)").monospacedDigit() }.width(70)
            TableColumn("Duration") { f in Text(Format.duration(f.duration)) }.width(80)
            TableColumn("Sampling") { f in Text(f.samplingInterval.map { "1:\($0)" } ?? "—") }.width(70)
            TableColumn("Country") { f in Text(f.enrichment.dstCountry ?? "—") }.width(60)
        }
        .accessibilityLabel("Flows table")        .contextMenu(forSelectionType: FlowRecord.ID.self) { ids in
            if let id = ids.first, let f = rows.first(where: { $0.id == id }) {
                Button("Filter by source \(f.srcIP)") { ipText = f.srcIP.description; Task { await load(reset: true) } }
                Button("Filter by destination \(f.dstIP)") { ipText = f.dstIP.description; Task { await load(reset: true) } }
                Button("Filter by port \(f.dstPort)") { portText = "\(f.dstPort)"; Task { await load(reset: true) } }
            }
        }
    }

    private var statusBar: some View {
        HStack(spacing: 12) {
            if loading { ProgressView().controlSize(.small) }
            Text(statusText).font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).font(.caption).foregroundStyle(.red).lineLimit(1) }
            Spacer()
            if page?.nextCursor != nil { Button("Load more") { Task { await load(reset: false) } }.disabled(loading) }
            TextField("Save search as…", text: $savedName).textFieldStyle(.roundedBorder).frame(width: 160).onSubmit { saveSearch() }
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
    }

    private var statusText: String {
        guard let p = page else { return analytics.engine == nil ? "Store not open yet" : "" }
        return "\(rows.count) flows · \(p.segmentsScanned) segments · \(Format.duration(p.elapsed))\(p.nextCursor != nil ? " · more available" : "")"
    }

    private func currentFilter() -> RecordFilter {
        var f = RecordFilter(range: preset.range())
        let ip = ipText.trimmingCharacters(in: .whitespaces)
        if !ip.isEmpty { if ip.contains("/"), let p = IPPrefix(ip) { f.prefix = p } else if let a = IPAddress(ip) { f.anyIP = a } }
        if let p = UInt16(portText.trimmingCharacters(in: .whitespaces)) { f.ports = [p] }
        if proto != 0 { f.protocols = [UInt8(proto)] }
        if let d = direction { f.directions = [d] }
        f.origin = model.health?.demoWorkspace == true ? .simulated : .live
        return f
    }

    private func load(reset: Bool) async {
        task?.cancel()
        analytics.ensureOpen(root: URL(fileURLWithPath: model.storageRootPath))
        var draft = FlowQuery(filter: currentFilter()); draft.sort = sort; draft.direction = descending ? .descending : .ascending; draft.limit = 500
        if !reset { draft.cursor = page?.nextCursor; guard draft.cursor != nil else { return } }
        let q = draft
        loading = true
        let t = Task { () -> QueryPage<FlowRecord>? in try await analytics.run { try await $0.flows(q) } }
        task = t
        do {
            if let p = try await t.value { if reset { rows = p.rows } else { rows += p.rows }; page = p; error = nil }
        } catch is CancellationError { } catch { self.error = error.localizedDescription }
        loading = false
    }

    private func saveSearch() {
        guard !savedName.isEmpty else { return }
        model.saveSearch(name: savedName, view: "flows", query: currentFilter())
        savedName = ""
    }

    private func exportCSV() {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.commaSeparatedText]; panel.nameFieldStringValue = "flows.csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var csv = "start_time,end_time,direction,src_ip,src_port,dst_ip,dst_port,protocol,packets,octets,sampling,country,asn,exporter\n"
        for f in rows {
            csv += "\(f.startTime),\(f.endTime),\(f.enrichment.direction.label),\(f.srcIP),\(f.srcPort),\(f.dstIP),\(f.dstPort),\(f.protocolName),\(f.packets),\(f.octets),\(f.samplingInterval.map(String.init) ?? ""),\(f.enrichment.dstCountry ?? ""),\(f.enrichment.dstASN.map(String.init) ?? ""),\(f.exporter)\n"
        }
        try? csv.write(to: url, atomically: true, encoding: .utf8)
    }
}

enum FlowColumn: String, CaseIterable, Identifiable {
    case time, dir, src, dst, proto, bytes, pkts, dur, sampling, country
    var id: String { rawValue }
    var title: String { switch self { case .time: "Time"; case .dir: "Direction"; case .src: "Source"; case .dst: "Destination"; case .proto: "Protocol"; case .bytes: "Bytes"; case .pkts: "Packets"; case .dur: "Duration"; case .sampling: "Sampling"; case .country: "Country" } }
}

struct FlowDetail: View {
    let flow: FlowRecord
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Flow \(flow.id)").font(.headline)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                ForEach(FlowFields.describe(flow), id: \.0) { k, v in
                    GridRow { Text(k).foregroundStyle(.secondary).font(.caption); Text(v).font(.caption.monospaced()).textSelection(.enabled) }
                }
            }
        }
    }
}
