import SwiftUI
import NetSentryExport
import NetSentryAnalytics
import NetSentryCore

/// Historical syslog events: structured table with severity/type/action filters and the raw message.
struct EventsView: View {
    @Environment(AppModel.self) private var model
    @Environment(AnalyticsService.self) private var analytics
    @State private var preset: RangePreset = .h1
    @State private var text = ""
    @State private var type: EventType? = nil
    @State private var minSeverity: SyslogSeverity = .debug
    @State private var action: FirewallAction? = nil
    @State private var page: QueryPage<SyslogEvent>?
    @State private var rows: [SyslogEvent] = []
    @State private var showExport = false
    @State private var selection: SyslogEvent.ID?
    @State private var loading = false
    @State private var error: String?
    @State private var task: Task<(QueryPage<SyslogEvent>?, [EventCountRow]), any Error>?
    @State private var counts: [EventCountRow] = []
    @State private var saveName = ""

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 10) {
                Picker("Range", selection: $preset) { ForEach(RangePreset.allCases) { Text($0.rawValue).tag($0) } }.frame(width: 120).labelsHidden()
                TextField("Message, rule, host…", text: $text).textFieldStyle(.roundedBorder).frame(width: 220).onSubmit { Task { await load(reset: true) } }
                Picker("Type", selection: $type) { Text("Any type").tag(EventType?.none); ForEach(EventType.allCases, id: \.self) { Text($0.label).tag(EventType?.some($0)) } }.frame(width: 140).labelsHidden()
                Picker("Severity", selection: $minSeverity) { ForEach(SyslogSeverity.allCases, id: \.self) { Text("≥ \($0.label)").tag($0) } }.frame(width: 130).labelsHidden()
                Picker("Action", selection: $action) { Text("Any action").tag(FirewallAction?.none); ForEach(FirewallAction.allCases.filter { $0 != .unknown }, id: \.self) { Text($0.label).tag(FirewallAction?.some($0)) } }.frame(width: 130).labelsHidden()
                Button("Search") { Task { await load(reset: true) } }.keyboardShortcut(.return, modifiers: .command)
                SavedSearchMenu(view: "events") { f in
                    text = f.text ?? ""; type = f.eventTypes.first; action = f.actions.first
                    minSeverity = f.severities.max() ?? .debug
                    Task { await load(reset: true) }
                }
                TextField("Save as…", text: $saveName).textFieldStyle(.roundedBorder).frame(width: 120).onSubmit {
                    guard !saveName.isEmpty else { return }; model.saveSearch(name: saveName, view: "events", query: filter()); saveName = ""
                }
                if !counts.isEmpty { Text(counts.prefix(4).map { "\(EventType(rawValue: UInt8($0.key) ?? 0)?.label ?? $0.key) \($0.count)" }.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary) }
            }
            .padding(10)
            }
            Divider()
            HSplitView {
                Table(rows, selection: $selection) {
                    TableColumn("Time") { e in Text(e.effectiveTime.date.formatted(date: .abbreviated, time: .standard)).monospacedDigit() }.width(min: 150, ideal: 170)
                    TableColumn("Severity") { e in StatusBadge(text: e.severity.label, kind: e.severity <= .error ? .error : (e.severity == .warning ? .warning : .neutral)) }.width(90)
                    TableColumn("Type") { e in Text(e.eventType.label) }.width(90)
                    TableColumn("Action") { e in Text(e.action?.label ?? "") }.width(70)
                    TableColumn("Source") { e in Text(e.srcIP.map { "\($0)\(e.srcPort.map { ":\($0)" } ?? "")" } ?? (e.hostname ?? "")).monospaced() }
                    TableColumn("Destination") { e in Text(e.dstIP.map { "\($0)\(e.dstPort.map { ":\($0)" } ?? "")" } ?? "").monospaced() }
                    TableColumn("Rule / Signature") { e in Text(e.ruleName ?? e.idsSignature ?? e.username ?? "") }
                    TableColumn("Message") { e in Text(e.message).lineLimit(1) }
                }
                .accessibilityLabel("Events table")                .frame(minWidth: 320)
                if let id = selection, let e = rows.first(where: { $0.id == id }) {
                    ScrollView { LiveInspector(row: LiveRow(id: 0, time: e.effectiveTime, flow: nil, event: e)) }.frame(minWidth: 300, idealWidth: 380)
                } else {
                    ContentUnavailableView("Select an event", systemImage: "sidebar.right", description: Text("Structured fields, parser and version, and the raw message.")).frame(minWidth: 300, idealWidth: 380)
                }
            }
            HStack {
                if loading { ProgressView().controlSize(.small) }
                Text(page.map { "\(rows.count) events · \($0.segmentsScanned) segments · \(Format.duration($0.elapsed))" } ?? (analytics.engine == nil ? "Store not open yet" : "")).font(.caption).foregroundStyle(.secondary)
                if let error { Text(error).font(.caption).foregroundStyle(.red) }
                Spacer()
                if page?.nextCursor != nil { Button("Load more") { Task { await load(reset: false) } }.disabled(loading) }
                Button("Export…") { showExport = true }.disabled(rows.isEmpty).keyboardShortcut("e", modifiers: .command)
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
        }
        .sheet(isPresented: $showExport) {
            let prefixes = model.configuration.internalPrefixes
            ExportSheet(title: "Export \(rows.count) loaded events") { format, policy in
                let name = "events-\(Date.now.formatted(.iso8601.year().month().day()))"
                let isInternal: (IPAddress) -> Bool = { model.isInternalAddress($0, prefixes: prefixes) }
                switch format {
                case .csv: _ = ExportService.save(data: Data(RecordExport.eventsCSV(rows, policy: policy, isInternal: isInternal).utf8), suggestedName: name + ".csv", type: .commaSeparatedText)
                case .json: if let d = try? RecordExport.eventsJSON(rows, policy: policy, isInternal: isInternal) { _ = ExportService.save(data: d, suggestedName: name + ".json", type: .json) }
                }
            }
        }
        .task { await load(reset: true) }
        .onChange(of: preset) { _, _ in Task { await load(reset: true) } }
        .onChange(of: type) { _, _ in Task { await load(reset: true) } }
        .onChange(of: minSeverity) { _, _ in Task { await load(reset: true) } }
        .onChange(of: action) { _, _ in Task { await load(reset: true) } }
    }

    private func filter() -> RecordFilter {
        var f = RecordFilter(range: preset.range())
        if !text.trimmingCharacters(in: .whitespaces).isEmpty { f.text = text }
        if let t = type { f.eventTypes = [t] }
        if minSeverity != .debug { f.severities = SyslogSeverity.allCases.filter { $0 <= minSeverity } }
        if let a = action { f.actions = [a] }
        f.origin = model.health?.demoWorkspace == true ? .simulated : .live
        return f
    }

    private func load(reset: Bool) async {
        task?.cancel()
        analytics.ensureOpen(root: URL(fileURLWithPath: model.storageRootPath))
        var draft = EventQuery(filter: filter()); draft.limit = 500
        if !reset { draft.cursor = page?.nextCursor; guard draft.cursor != nil else { return } }
        let q = draft
        loading = true
        let f = q.filter
        let t = Task { () -> (QueryPage<SyslogEvent>?, [EventCountRow]) in
            let p = try await analytics.run { try await $0.events(q) }
            let c = (try? await analytics.run { try await $0.eventCounts(f, by: "event_type") }) ?? []
            return (p, c)
        }
        task = t
        do {
            let (p, c) = try await t.value
            if let p { if reset { rows = p.rows } else { rows += p.rows }; page = p; error = nil }
            counts = c
        } catch is CancellationError { } catch { self.error = error.localizedDescription }
        loading = false
    }
}
