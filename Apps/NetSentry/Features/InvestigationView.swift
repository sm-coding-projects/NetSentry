import SwiftUI
import NetSentryExport
import NetSentryAnalytics
import NetSentryCore
import NetSentryCorrelation
import NetSentryPersistence

/// Unified timeline for an anchor (flow, event, client, address, alert or time range) with a window before/after.
struct InvestigationView: View {
    @Environment(AppModel.self) private var model
    @Environment(AnalyticsService.self) private var analytics
    @State private var investigation: Investigation?
    @State private var window: Double = 15   // minutes before/after
    @State private var kinds: Set<TimelineEntry.Kind> = Set(TimelineEntry.Kind.allCases)
    @State private var selection: TimelineEntry.ID?
    @State private var loading = false
    @State private var error: String?
    @State private var addressText = ""
    @State private var showExport = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text(model.investigationAnchor?.label ?? "No anchor").font(.headline).lineLimit(1)
                Spacer()
                TextField("Investigate address…", text: $addressText).textFieldStyle(.roundedBorder).frame(width: 180).onSubmit { if let ip = IPAddress(addressText) { model.openInvestigation(.address(ip)) } }
                Picker("Window", selection: $window) { Text("±5 min").tag(5.0); Text("±15 min").tag(15.0); Text("±1 h").tag(60.0); Text("±6 h").tag(360.0); Text("±24 h").tag(1440.0) }.frame(width: 110).labelsHidden()
                Menu("Show") { ForEach(TimelineEntry.Kind.allCases, id: \.self) { k in Toggle(k.rawValue, isOn: Binding(get: { kinds.contains(k) }, set: { on in if on { kinds.insert(k) } else { kinds.remove(k) } })) } }.frame(width: 80)
                if loading { ProgressView().controlSize(.small) }
                Button("Export bundle…") { showExport = true }.disabled(investigation == nil)
                Button("Reload") { Task { await load() } }.keyboardShortcut("r", modifiers: .command)
            }
            .padding(10)
            Divider()
            if let inv = investigation {
                GeometryReader { geo in
                HSplitView {
                    Table(inv.entries.filter { kinds.contains($0.kind) }, selection: $selection) {
                        TableColumn("Time") { e in Text(e.time.date.formatted(date: .omitted, time: .standard)).monospacedDigit().fontWeight(e.isAnchor ? .bold : .regular) }.width(90)
                        TableColumn("Kind") { e in StatusBadge(text: e.kind.rawValue, kind: badge(e.kind)) }.width(90)
                        TableColumn("What") { e in Text(e.title).lineLimit(1).fontWeight(e.isAnchor ? .bold : .regular) }
                        TableColumn("Relation") { e in Text(e.relations.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary) }.width(220)
                    }
                    .accessibilityLabel("Timeline table").frame(minWidth: 560).frame(height: geo.size.height)
                    if let id = selection, let e = inv.entries.first(where: { $0.id == id }) { entryDetail(e).frame(minWidth: 320, idealWidth: 380).frame(height: geo.size.height) }
                    else { ContentUnavailableView("Select an entry", systemImage: "sidebar.right", description: Text("Full record. Pivot from any address or client into a new investigation.")).frame(minWidth: 320, idealWidth: 380).frame(height: geo.size.height) }
                }
                .frame(width: geo.size.width, height: geo.size.height)
                }
                HStack {
                    Text("\(inv.entries.count) entries · \(Format.duration(inv.elapsed))\(inv.truncated ? " · truncated, narrow the window" : "") · relations describe shared attributes and timing, not causes").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                }.padding(8)
            } else if let error {
                Text(error).foregroundStyle(.red).padding()
            } else {
                ContentUnavailableView("Start an investigation", systemImage: "magnifyingglass", description: Text("Pick a flow, event, client, destination or alert anywhere in the app, or enter an address above.")).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .task { await load() }
        .sheet(isPresented: $showExport) {
            let prefixes = model.configuration.internalPrefixes
            ExportSheet(title: "Export investigation bundle (JSON)", formats: [.json]) { _, policy in
                guard let inv = investigation else { return }
                if let d = try? IncidentExport.bundle(inv, alert: nil, policy: policy, isInternal: { model.isInternalAddress($0, prefixes: prefixes) }) {
                    _ = ExportService.save(data: d, suggestedName: "investigation-\(Date.now.formatted(.iso8601.year().month().day()))-\(Int(Date.now.timeIntervalSince1970)).json", type: .json)
                }
            }
        }
        .onChange(of: model.investigationAnchor) { _, _ in Task { await load() } }
        .onChange(of: window) { _, _ in Task { await load() } }
    }

    private func badge(_ k: TimelineEntry.Kind) -> StatusBadge.Kind { switch k { case .ids, .alert: .error; case .firewall, .gap: .warning; case .annotation: .ok; default: .neutral } }

    @ViewBuilder private func entryDetail(_ e: TimelineEntry) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                Text(e.title).font(.headline)
                Text(e.detail).font(.callout)
                if !e.relations.isEmpty { Text("Relations: " + e.relations.joined(separator: "; ")).font(.caption).foregroundStyle(.secondary) }
                if let f = e.flow {
                    HStack { Button("Pivot to \(f.srcIP)") { model.openInvestigation(.address(f.srcIP)) }; Button("Pivot to \(f.dstIP)") { model.openInvestigation(.address(f.dstIP)) } }
                    FlowDetail(flow: f)
                }
                if let ev = e.event {
                    HStack { if let s = ev.srcIP { Button("Pivot to \(s)") { model.openInvestigation(.address(s)) } }; if let d = ev.dstIP { Button("Pivot to \(d)") { model.openInvestigation(.address(d)) } } }
                    LiveInspector(row: LiveRow(id: 0, time: ev.effectiveTime, flow: nil, event: ev))
                }
                if let g = e.gap { Text("Gap \(g.kind.label) from \(Format.time(g.start)) to \(g.end.map { Format.time($0) } ?? "now"): \(g.reason)").font(.callout).foregroundStyle(.orange) }
                if e.kind == .alert, let id = e.alertID { Button("Open alert") { model.pendingAlertID = id; model.requestedSection = .security } }
            }.padding(12)
        }
    }

    private func load() async {
        guard let anchor = model.investigationAnchor else { return }
        analytics.ensureOpen(root: URL(fileURLWithPath: model.storageRootPath))
        guard let engine = analytics.engine, let meta = try? MetaStore(root: URL(fileURLWithPath: model.storageRootPath), readOnly: true) else { error = analytics.openError; return }
        loading = true; defer { loading = false }
        let center = anchor.time ?? model.investigationTime ?? .now
        let half = Duration.seconds(Int64(window * 60))
        var req = InvestigationRequest(anchor: anchor, range: TimeRange(start: Timestamp(microseconds: center.microseconds - half.microsecondsValue), end: Timestamp(microseconds: center.microseconds + half.microsecondsValue)))
        req.origin = model.health?.demoWorkspace == true ? .simulated : .live
        do { investigation = try await TimelineBuilder(engine: engine, meta: meta).build(req); error = nil } catch { self.error = error.localizedDescription }
    }
}
