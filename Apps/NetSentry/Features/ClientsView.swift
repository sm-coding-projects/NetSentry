import SwiftUI
import NetSentryAnalytics
import NetSentryCore
import NetSentryDetection
import NetSentryEnrichment

/// Client inventory keyed by resolved identity: name, hostname, MAC, VLAN, address history, tags, notes, trust,
/// merge/split, expectations, plus traffic history and top destinations/ports for the range.
struct ClientsView: View {
    @Environment(AppModel.self) private var model
    @Environment(AnalyticsService.self) private var analytics
    @State private var preset: RangePreset = .h24
    @State private var search = ""
    @State private var clients: [ClientIdentity] = []
    @State private var traffic: [String: TopNRow] = [:]   // by address
    @State private var selection: ClientIdentity.ID?
    @State private var detail: [TopNRow] = []
    @State private var detailPorts: [TopNRow] = []
    @State private var series: [TimeBucket] = []
    @State private var alerts: [NetSentryDetection.Alert] = []
    @State private var loading = false
    @State private var error: String?
    @State private var sortByTraffic = true

    private var security: SecurityClient { SecurityClient(client: model.client) }
    private func bytes(_ c: ClientIdentity) -> Int64 { c.addresses.reduce(0) { $0 + (traffic[$1]?.bytes ?? 0) } }
    var filtered: [ClientIdentity] {
        let base = search.isEmpty ? clients : clients.filter { c in c.label.localizedCaseInsensitiveContains(search) || c.addresses.contains { $0.contains(search) } || (c.primaryMAC ?? "").contains(search.lowercased()) || c.tags.contains { $0.localizedCaseInsensitiveContains(search) } }
        return sortByTraffic ? base.sorted { bytes($0) > $1.addresses.reduce(0) { $0 + (traffic[$1]?.bytes ?? 0) } } : base.sorted { $0.lastSeen > $1.lastSeen }
    }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                HStack {
                    Picker("Range", selection: $preset) { ForEach(RangePreset.allCases) { Text($0.rawValue).tag($0) } }.frame(width: 120).labelsHidden()
                    TextField("Search name, address, MAC or tag", text: $search).textFieldStyle(.roundedBorder)
                    Toggle("By traffic", isOn: $sortByTraffic).toggleStyle(.checkbox)
                    if loading { ProgressView().controlSize(.small) }
                    Button("Refresh") { Task { await load() } }.keyboardShortcut("r", modifiers: .command)
                }.padding(10)
                Table(filtered, selection: $selection) {
                    TableColumn("Client") { c in
                        HStack(spacing: 4) { if c.trusted { Image(systemName: "checkmark.shield").foregroundStyle(.green).accessibilityLabel("Trusted") }; Text(c.label) }
                    }
                    TableColumn("Address") { c in Text(c.addresses.first ?? "—").monospaced() }.width(120)
                    TableColumn("VLAN") { c in Text(c.vlanID.map(String.init) ?? "—") }.width(45)
                    TableColumn("Bytes out") { c in Text(Format.bytes(bytes(c))).monospacedDigit() }.width(90)
                    TableColumn("Last seen") { c in Text(Format.relative(c.lastSeen)) }.width(100)
                }
                .accessibilityLabel("Clients table")
                Text("\(clients.count) clients known · identities come from IPFIX MAC/VLAN and DHCP syslog; names, tags and notes are yours.").font(.caption).foregroundStyle(.secondary).padding(6)
                if let error { Text(error).font(.caption).foregroundStyle(.red).padding(6) }
            }
            .frame(minWidth: 320)
            Group {
                if let id = selection, let c = clients.first(where: { $0.id == id }) {
                    ClientDetailView(client: c, others: clients.filter { $0.id != id }, series: series, range: preset.range(), detail: detail, detailPorts: detailPorts, alerts: alerts,
                                     onChange: { updated in if let u = updated, let i = clients.firstIndex(where: { $0.id == u.id }) { clients[i] = u } ; Task { await load() } }, onError: { error = $0 })
                } else {
                    ContentUnavailableView("Select a client", systemImage: "desktopcomputer", description: Text("Identity, address history, traffic, alerts and your notes for the selected client."))
                }
            }
            .frame(minWidth: 300)
        }
        .task { await load() }
        .onChange(of: preset) { _, _ in Task { await load() } }
        .onChange(of: selection) { _, _ in Task { await loadDetail() } }
    }

    private var origin: Origin { model.health?.demoWorkspace == true ? .simulated : .live }

    private func load() async {
        analytics.ensureOpen(root: URL(fileURLWithPath: model.storageRootPath))
        loading = true; defer { loading = false }
        do { clients = try await security.clients(); error = nil } catch { self.error = "Collector not reachable: \(error.localizedDescription)" }
        let f: RecordFilter = { var x = RecordFilter(range: preset.range()); x.directions = [.outbound]; x.origin = origin; return x }()
        do { let rows = try await analytics.run { try await $0.topN(TopNQuery(filter: f, dimension: .srcIP, limit: 2000)) } ?? []; traffic = Dictionary(rows.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a }) }
        catch { self.error = error.localizedDescription }
        await loadDetail()
    }

    private func loadDetail() async {
        guard let id = selection, let c = clients.first(where: { $0.id == id }) else { return }
        let f: RecordFilter = { var x = RecordFilter(range: preset.range()); x.clientID = id; x.directions = [.outbound]; x.origin = origin; return x }()
        let g: RecordFilter = { var x = RecordFilter(range: preset.range()); x.clientID = id; x.origin = origin; return x }()
        let bucket = preset.bucket
        do {
            detail = try await analytics.run { try await $0.topN(TopNQuery(filter: f, dimension: .dstIP, limit: 15)) } ?? []
            detailPorts = try await analytics.run { try await $0.topN(TopNQuery(filter: f, dimension: .dstPort, limit: 10)) } ?? []
            series = try await analytics.run { try await $0.timeSeries(g, bucket: bucket) } ?? []
            alerts = (try? await security.alerts(clientID: c.id)) ?? []
        } catch { self.error = error.localizedDescription }
    }
}

struct ClientDetailView: View {
    @Environment(AppModel.self) private var model
    let client: ClientIdentity
    let others: [ClientIdentity]
    let series: [TimeBucket]
    let range: TimeRange
    let detail: [TopNRow]
    let detailPorts: [TopNRow]
    let alerts: [NetSentryDetection.Alert]
    let onChange: (ClientIdentity?) -> Void
    let onError: (String) -> Void
    @State private var name = ""
    @State private var notes = ""
    @State private var tags = ""
    @State private var mergeTarget: Int64?
    @State private var expectKind = "destination"
    @State private var expectValue = ""
    private var security: SecurityClient { SecurityClient(client: model.client) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    TextField("Display name", text: $name).textFieldStyle(.roundedBorder).font(.title3)
                    Button("Rename") { run { try await security.rename(client.id, name) } }.disabled(name == (client.displayName ?? ""))
                    Toggle("Trusted", isOn: Binding(get: { client.trusted }, set: { v in run { try await security.setTrusted(client.id, v) } })).toggleStyle(.switch)
                }
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                    GridRow { Text("Hostname").foregroundStyle(.secondary); Text(client.hostname ?? "unknown (learned from DHCP syslog)") }
                    GridRow { Text("MAC").foregroundStyle(.secondary); Text(client.primaryMAC ?? "unknown (learned from IPFIX)").monospaced() }
                    GridRow { Text("VLAN / network").foregroundStyle(.secondary); Text("\(client.vlanID.map(String.init) ?? "—") / \(client.networkID ?? "—")") }
                    GridRow { Text("Addresses").foregroundStyle(.secondary); Text(client.addresses.joined(separator: ", ")).monospaced().textSelection(.enabled) }
                    GridRow { Text("Seen").foregroundStyle(.secondary); Text("\(Format.time(client.firstSeen)) → \(Format.time(client.lastSeen))") }
                    GridRow { Text("Created by").foregroundStyle(.secondary); Text(client.createdBy) }
                }.font(.callout)
                HStack {
                    TextField("Tags (comma separated)", text: $tags).textFieldStyle(.roundedBorder)
                    Button("Save tags") { run { try await security.setTags(client.id, tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }) } }
                }
                GroupBox("Notes") {
                    VStack(alignment: .trailing) {
                        TextEditor(text: $notes).frame(minHeight: 60).font(.callout)
                        Button("Save notes") { run { try await security.setNotes(client.id, notes) } }.disabled(notes == (client.notes ?? ""))
                    }
                }
                HStack {
                    Button("Investigate") { model.openInvestigation(.client(client.id, label: client.label, addresses: client.addresses)) }
                    Menu("Merge into…") {
                        ForEach(others.sorted { $0.label < $1.label }) { o in Button("\(o.label) (\(o.addresses.first ?? "no address"))") { run { try await security.merge(client.id, into: o.id) } } }
                    }.frame(width: 130)
                    if client.addresses.count > 1 {
                        Menu("Split address…") { ForEach(client.addresses, id: \.self) { a in Button(a) { run { try await security.split(client.id, ip: a) } } } }.frame(width: 130)
                    }
                }
                GroupBox("Expected for this client") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Expectations silence first-seen and unusual-destination findings for this client. They are explicit and reviewable in Settings.").font(.caption).foregroundStyle(.secondary)
                        HStack {
                            Picker("", selection: $expectKind) { Text("Destination IP").tag("destination"); Text("Country").tag("country"); Text("ASN").tag("asn"); Text("Port").tag("port"); Text("Resolver").tag("resolver") }.frame(width: 130).labelsHidden()
                            TextField("value", text: $expectValue).textFieldStyle(.roundedBorder)
                            Button("Add") { Task { do { try await security.addExpectation(scopeType: "client", scopeValue: "\(client.id)", kind: expectKind, value: expectValue); expectValue = "" } catch { onError(error.localizedDescription) } } }.disabled(expectValue.isEmpty)
                        }
                    }
                }
                if !alerts.isEmpty {
                    GroupBox("Alerts (\(alerts.count))") {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(alerts.prefix(10)) { a in
                                HStack { StatusBadge(text: a.severity.label, kind: a.severity >= .high ? .error : .warning); Text(a.title).lineLimit(1); Spacer(); Text(a.state.rawValue).font(.caption).foregroundStyle(.secondary) }
                                    .onTapGesture { model.pendingAlertID = a.id; model.requestedSection = .security }
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                GroupBox("Traffic") { TrafficChart(series: series, gaps: [], range: range) }
                TopList(title: "Top destinations", rows: detail)
                TopList(title: "Top ports", rows: detailPorts)
            }.padding(16)
        }
        .onAppear { sync() }
        .onChange(of: client) { _, _ in sync() }
    }

    private func sync() { name = client.displayName ?? ""; notes = client.notes ?? ""; tags = client.tags.joined(separator: ", ") }
    private func run(_ op: @escaping () async throws -> ClientIdentity?) { Task { do { onChange(try await op()) } catch { onError(error.localizedDescription) } } }
}
