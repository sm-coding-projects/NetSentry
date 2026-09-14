import SwiftUI
import NetSentryCorrelation
import NetSentryExport
import NetSentryPersistence
import NetSentryAnalytics
import NetSentryCore
import NetSentryDetection
import NetSentryIPC

/// Alert workflow: filter by state/severity, read evidence and explanation, act (acknowledge, resolve, reopen,
/// suppress, mark expected, note) and pivot into an investigation.
struct SecurityView: View {
    @Environment(AppModel.self) private var model
    @State private var alerts: [NetSentryDetection.Alert] = []
    @State private var states: Set<AlertState> = [.open, .acknowledged]
    @State private var minSeverity: AlertSeverity = .info
    @State private var selection: NetSentryDetection.Alert.ID?
    @State private var error: String?
    @State private var note = ""
    @State private var loading = false
    @State private var showRules = false
    @State private var exportKind: ExportKind?
    @Environment(AnalyticsService.self) private var analytics
    enum ExportKind: String, Identifiable { case alerts, report; var id: String { rawValue } }

    private var security: SecurityClient { SecurityClient(client: model.client) }
    var filtered: [NetSentryDetection.Alert] { alerts.filter { states.contains($0.state) && $0.severity >= minSeverity } }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 10) {
                    ForEach(AlertState.allCases, id: \.self) { s in
                        Toggle(s.rawValue.capitalized, isOn: Binding(get: { states.contains(s) }, set: { on in if on { states.insert(s) } else { states.remove(s) } })).toggleStyle(.checkbox)
                    }
                    Picker("Min severity", selection: $minSeverity) { ForEach(AlertSeverity.allCases, id: \.self) { Text("≥ \($0.label)").tag($0) } }.frame(width: 120).labelsHidden()
                    if loading { ProgressView().controlSize(.small) }
                    Button("Rules…") { showRules = true }
                    Menu("Export") {
                        Button("Export \(filtered.count) alerts…") { exportKind = .alerts }
                        Button("Incident report for selected alert…") { exportKind = .report }.disabled(selection == nil)
                    }.frame(width: 90)
                    Button("Refresh") { Task { await load() } }.keyboardShortcut("r", modifiers: .command)
                }
                .padding(10)
                }
                Table(filtered, selection: $selection) {
                    TableColumn("Severity") { a in StatusBadge(text: a.severity.label, kind: a.severity >= .high ? .error : (a.severity == .medium ? .warning : .neutral)) }.width(80)
                    TableColumn("State") { a in Text(a.state.rawValue.capitalized) }.width(90)
                    TableColumn("NetSentryDetection.Alert") { a in Text(a.title).lineLimit(1) }
                    TableColumn("Rule") { a in Text(a.ruleName) }.width(160)
                    TableColumn("Count") { a in Text("\(a.occurrenceCount)").monospacedDigit() }.width(50)
                    TableColumn("Last") { a in Text(Format.relative(a.lastOccurrence)) }.width(110)
                }
                .accessibilityLabel("Alerts table")
                if let error { Text(error).font(.caption).foregroundStyle(.red).padding(6) }
            }
            .frame(minWidth: 320)
            Group {
                if let id = selection, let a = alerts.first(where: { $0.id == id }) { AlertDetailView(alert: a, note: $note, onChange: { updated in replace(updated) }, onError: { error = $0 }) }
                else { ContentUnavailableView("Select an alert", systemImage: "shield.lefthalf.filled", description: Text("Evidence, the reason it triggered, the baseline used, and the supporting flows and events.")) }
            }
            .frame(minWidth: 300)
        }
        .task { await load() }
        .onChange(of: model.lastAlertEvent) { _, _ in Task { await load() } }
        .onChange(of: model.pendingAlertID) { _, id in if let id { selection = id; model.pendingAlertID = nil } }
        .sheet(isPresented: $showRules) { RulesSheet().environment(model).frame(width: 720, height: 560) }
        .sheet(item: $exportKind) { kind in
            let prefixes = model.configuration.internalPrefixes
            let isInternal: (IPAddress) -> Bool = { model.isInternalAddress($0, prefixes: prefixes) }
            switch kind {
            case .alerts:
                ExportSheet(title: "Export \(filtered.count) alerts") { format, policy in
                    let name = "alerts-\(Date.now.formatted(.iso8601.year().month().day()))"
                    switch format {
                    case .csv: _ = ExportService.save(data: Data(IncidentExport.alertsCSV(filtered, policy: policy, isInternal: isInternal).utf8), suggestedName: name + ".csv", type: .commaSeparatedText)
                    case .json: if let d = try? IncidentExport.alertsJSON(filtered, policy: policy, isInternal: isInternal) { _ = ExportService.save(data: d, suggestedName: name + ".json", type: .json) }
                    }
                }
            case .report:
                ExportSheet(title: "Incident report (Markdown) with a ±15 minute timeline", formats: [.json]) { _, policy in
                    guard let id = selection, let a = alerts.first(where: { $0.id == id }) else { return }
                    Task { await exportReport(a, policy: policy, isInternal: isInternal) }
                }
            }
        }
    }

    private func load() async {
        loading = true; defer { loading = false }
        do { alerts = try await security.alerts(); error = nil } catch { self.error = error.localizedDescription }
        if let id = model.pendingAlertID { selection = id; model.pendingAlertID = nil }
    }
    private func exportReport(_ a: NetSentryDetection.Alert, policy: RedactionPolicy, isInternal: @escaping (IPAddress) -> Bool) async {
        analytics.ensureOpen(root: URL(fileURLWithPath: model.storageRootPath))
        var inv: Investigation?
        if let engine = analytics.engine, let meta = try? MetaStore(root: URL(fileURLWithPath: model.storageRootPath), readOnly: true) {
            let addrs = [a.entity.kind == "ip" ? a.entity.id : "", a.evidence["destination"] ?? "", a.evidence["source"] ?? ""].filter { !$0.isEmpty }
            var req = InvestigationRequest(anchor: .alert(id: a.id, title: a.title, time: a.firstOccurrence, clientID: a.clientID, addresses: addrs, flowIDs: a.flowIDs, eventIDs: a.eventIDs),
                                           range: TimeRange(start: a.firstOccurrence + .seconds(-900), end: a.lastOccurrence + .seconds(900)))
            req.origin = a.origin
            inv = try? await TimelineBuilder(engine: engine, meta: meta).build(req)
        }
        var clientLabel: String?
        if let id = a.clientID { clientLabel = (try? await SecurityClient(client: model.client).client(id: id))?.label }
        let md = IncidentExport.markdown(alert: a, clientLabel: clientLabel, investigation: inv, policy: policy, isInternal: isInternal)
        _ = ExportService.save(data: Data(md.utf8), suggestedName: "incident-\(a.id)-\(a.ruleName).md", type: ExportService.markdown)
    }

    private func replace(_ a: NetSentryDetection.Alert?) { guard let a else { return }; if let i = alerts.firstIndex(where: { $0.id == a.id }) { alerts[i] = a } }
}

struct AlertDetailView: View {
    @Environment(AppModel.self) private var model
    let alert: NetSentryDetection.Alert
    @Binding var note: String
    let onChange: (NetSentryDetection.Alert?) -> Void
    let onError: (String) -> Void
    private var security: SecurityClient { SecurityClient(client: model.client) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack { StatusBadge(text: alert.severity.label, kind: alert.severity >= .high ? .error : (alert.severity == .medium ? .warning : .neutral)); Text(alert.title).font(.headline); Spacer() }
                Text(alert.summary).font(.callout)
                LabeledContent("Rule", value: "\(alert.ruleName) v\(alert.ruleVersion)")
                LabeledContent("Detected", value: Format.time(alert.firstOccurrence) + (alert.occurrenceCount > 1 ? " · \(alert.occurrenceCount) occurrences, last \(Format.time(alert.lastOccurrence))" : ""))
                LabeledContent("Entity", value: "\(alert.entity.kind): \(alert.entity.label)")
                if let c = alert.clientID { LabeledContent("Client", value: "#\(c)") }
                GroupBox("Why it triggered") { Text(LocalizedStringKey(alert.explanation)).font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                if let b = alert.baseline {
                    GroupBox("Baseline / threshold") { Text("\(b.kind): \(String(format: "%g", b.value)) \(b.unit) over \(b.period) (\(b.samples) samples)").font(.callout).frame(maxWidth: .infinity, alignment: .leading) }
                }
                GroupBox("Evidence") {
                    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 3) {
                        ForEach(alert.evidence.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in GridRow { Text(k).font(.caption).foregroundStyle(.secondary); Text(v).font(.caption.monospaced()).textSelection(.enabled) } }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    Text("\(alert.flowIDs.count) flows · \(alert.eventIDs.count) events referenced\(alert.flowIDs.isEmpty && alert.eventIDs.isEmpty ? "" : " (open the investigation to see them)")").font(.caption).foregroundStyle(.secondary)
                }
                GroupBox("Recommended investigation") { VStack(alignment: .leading, spacing: 4) { ForEach(alert.steps, id: \.self) { Text("• \($0)").font(.callout) } }.frame(maxWidth: .infinity, alignment: .leading) }
                HStack {
                    Button("Investigate") { model.openInvestigation(.alert(id: alert.id, title: alert.title, time: alert.firstOccurrence, clientID: alert.clientID, addresses: [alert.entity.kind == "ip" ? alert.entity.id : alert.evidence["destination"] ?? "", alert.evidence["source"] ?? ""].filter { !$0.isEmpty }, flowIDs: alert.flowIDs, eventIDs: alert.eventIDs)) }.buttonStyle(.borderedProminent)
                    if alert.state == .open { Button("Acknowledge") { set(.acknowledged) } }
                    if alert.state != .resolved { Button("Resolve") { set(.resolved) } } else { Button("Reopen") { set(.open) } }
                    Menu("Suppress / expect") {
                        Button("Suppress this rule for this client") { suppress(["rule": alert.ruleName, "clientID": alert.clientID.map { "\($0)" } ?? ""]) }.disabled(alert.clientID == nil)
                        if let d = alert.evidence["destination"] ?? (alert.entity.kind == "ip" ? alert.entity.id : nil) { Button("Suppress this rule for destination \(d)") { suppress(["rule": alert.ruleName, "destination": d]) } }
                        Button("Suppress this rule for 24 hours") { suppress(["rule": alert.ruleName, "expiresAt": "\(Timestamp.now.microseconds + 86_400_000_000)"]) }
                        Divider()
                        if let c = alert.clientID {
                            if alert.entity.kind == "ip" { Button("Mark destination expected for this client") { expect("client", "\(c)", "destination", alert.entity.id) } }
                            if alert.entity.kind == "country" { Button("Mark country \(alert.entity.id) expected for this client") { expect("client", "\(c)", "country", alert.entity.id) } }
                            if alert.entity.kind == "asn" { Button("Mark ASN expected for this client") { expect("client", "\(c)", "asn", alert.entity.id) } }
                            if alert.entity.kind == "port" { Button("Mark port expected for this client") { expect("client", "\(c)", "port", alert.entity.id) } }
                            if let r = alert.evidence["resolver"] { Button("Mark resolver \(r) expected for this client") { expect("client", "\(c)", "resolver", r) } }
                        }
                        if alert.entity.kind == "vlan" { Button("Mark VLAN pair expected") { expect("global", "*", "vlan-pair", alert.entity.id) } }
                    }
                }
                GroupBox("Notes") {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(alert.notes) { n in Text("\(Format.time(n.createdAt)): \(n.text)").font(.caption) }
                        HStack { TextField("Add a note", text: $note).textFieldStyle(.roundedBorder); Button("Add") { addNote() }.disabled(note.isEmpty) }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(14)
        }
    }

    private func set(_ s: AlertState) { Task { do { onChange(try await security.setState(alert.id, s)) } catch { onError(error.localizedDescription) } } }
    private func addNote() { Task { do { onChange(try await security.addNote(alert.id, note)); note = "" } catch { onError(error.localizedDescription) } } }
    private func suppress(_ args: [String: String]) { Task { do { _ = try await security.addSuppression(args.merging(["reason": "from alert \(alert.id)"]) { a, _ in a }); onChange(try await security.setState(alert.id, .suppressed)) } catch { onError(error.localizedDescription) } } }
    private func expect(_ st: String, _ sv: String, _ k: String, _ v: String) { Task { do { try await security.addExpectation(scopeType: st, scopeValue: sv, kind: k, value: v, note: "from alert \(alert.id)"); onChange(try await security.setState(alert.id, .resolved)) } catch { onError(error.localizedDescription) } } }
}

/// Rule configuration: enable/disable and edit every parameter with its help text.
struct RulesSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var rules: [[String: String]] = []
    @State private var edits: [String: [String: Double]] = [:]
    @State private var error: String?
    private var security: SecurityClient { SecurityClient(client: model.client) }

    var body: some View {
        VStack(alignment: .leading) {
            Text("Detection rules").font(.headline)
            Text("Every rule is deterministic and explains its findings. Changes apply immediately to the running collector.").font(.caption).foregroundStyle(.secondary)
            List(rules, id: \.["name"]) { r in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Toggle(isOn: Binding(get: { r["enabled"] == "true" }, set: { on in Task { try? await security.setRule(r["name"] ?? "", enabled: on, params: [:]); await load() } })) { Text(r["title"] ?? "").font(.callout.bold()) }
                        Spacer(); Text("v\(r["version"] ?? "")  · default \(AlertSeverity(rawValue: UInt8(r["severity"] ?? "") ?? 0)?.label ?? "")").font(.caption).foregroundStyle(.secondary)
                    }
                    Text(r["description"] ?? "").font(.caption).foregroundStyle(.secondary)
                    ForEach(params(r), id: \.["key"]) { p in
                        HStack {
                            Text(p["label"] ?? "").frame(width: 170, alignment: .leading).font(.caption)
                            TextField("", value: Binding(get: { edits[r["name"] ?? ""]?[p["key"] ?? ""] ?? Double(p["value"] ?? "") ?? 0 }, set: { edits[r["name"] ?? "", default: [:]][p["key"] ?? ""] = $0 }), format: .number).frame(width: 110)
                            Text(p["unit"] ?? "").font(.caption).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                            Text(p["help"] ?? "").font(.caption2).foregroundStyle(.tertiary).lineLimit(2)
                        }
                    }
                    if let e = edits[r["name"] ?? ""], !e.isEmpty { Button("Apply") { Task { try? await security.setRule(r["name"] ?? "", enabled: nil, params: e); edits[r["name"] ?? ""] = nil; await load() } }.controlSize(.small) }
                }
                .padding(.vertical, 4)
            }
            if let error { Text(error).foregroundStyle(.red).font(.caption) }
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(16)
        .task { await load() }
    }
    private func params(_ r: [String: String]) -> [[String: String]] { (try? JSONDecoder().decode([[String: String]].self, from: Data((r["parameters"] ?? "[]").utf8))) ?? [] }
    private func load() async { do { rules = try await security.rules(); error = nil } catch { self.error = error.localizedDescription } }
}
