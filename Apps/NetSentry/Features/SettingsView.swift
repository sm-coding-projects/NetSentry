import SwiftUI
import NetSentryCore
import NetSentryDetection
import NetSentryIPC
import UniformTypeIdentifiers

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var draft: CollectorConfiguration?
    @State private var errors: [String] = []
    @State private var saved = false
    @State private var preview: RetentionPreviewRequest.Reply?
    @State private var pendingShrink: CollectorConfiguration?

    var body: some View {
        Form {
            if let d = draft { content(Binding(get: { d }, set: { draft = $0 })) } else { ProgressView().task { draft = model.configuration } }
        }
        .formStyle(.grouped)
        .onChange(of: model.configuration) { _, new in if draft == nil { draft = new } }
    }

    @ViewBuilder
    private func content(_ d: Binding<CollectorConfiguration>) -> some View {
        SwiftUI.Section("Background collector") {
            Toggle("Collect telemetry in the background", isOn: Binding(get: { model.configuration.collectionEnabled },
                                                                          set: { v in Task { await model.setCollectorEnabled(v); draft = model.configuration } }))
            LabeledContent("Login item", value: model.agentStatus)
            HStack {
                Button("Open Login Items…") { model.manager.openLoginItemsSettings() }
                Spacer()
                Text("The collector keeps running when this window is closed and restarts after a crash or login.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        SwiftUI.Section("Listeners") {
            ForEach(d.listeners) { l in
                HStack {
                    Toggle(isOn: l.enabled) { Text("\(l.wrappedValue.kind.label) over \(l.wrappedValue.transport.label)") }.frame(width: 190, alignment: .leading)
                    TextField("Port", value: l.port, format: .number.grouping(.never)).frame(width: 80).labelsHidden()
                        .accessibilityLabel("\(l.wrappedValue.kind.label) \(l.wrappedValue.transport.label) port")
                    Picker("Interface", selection: Binding(get: { l.wrappedValue.interface ?? "" }, set: { l.wrappedValue.interface = $0.isEmpty ? nil : $0 })) {
                        Text("All interfaces").tag("")
                        ForEach(NetworkInterfaces.list()) { i in Text("\(i.name) (\(i.addresses.first ?? ""))").tag(i.name) }
                    }.labelsHidden()
                }
            }
            Text("Ports 1024–65535. Configure the UniFi gateway to send NetFlow (IPFIX) and remote syslog to this Mac's address on these ports.")
                .font(.caption).foregroundStyle(.secondary)
        }
        SwiftUI.Section("Storage") {
            LabeledContent("Location") {
                HStack {
                    Text(d.wrappedValue.storageRoot).truncationMode(.middle).lineLimit(1)
                    Button("Choose…") { chooseFolder(d) }
                }
            }
            Picker("Maximum budget", selection: d.budgetBytes) {
                ForEach(StorageBudget.presetsGB, id: \.self) { gb in Text("\(gb) GB").tag(gb * 1_000_000_000) }
                if !StorageBudget.presetsGB.contains(d.wrappedValue.budgetBytes / 1_000_000_000) { Text("Custom (\(Format.bytes(d.wrappedValue.budgetBytes)))").tag(d.wrappedValue.budgetBytes) }
            }
            HStack {
                Text("Custom (GB)")
                TextField("GB", value: Binding(get: { Double(d.wrappedValue.budgetBytes) / 1e9 }, set: { d.wrappedValue.budgetBytes = StorageBudget.clamp(Int64($0 * 1e9)) }),
                          format: .number.precision(.fractionLength(0...1))).frame(width: 90)
                Text("5–500 GB. Treated as a ceiling; nothing is preallocated. Shrinking previews deletions first (Phase 3).").font(.caption).foregroundStyle(.secondary)
            }
        }
        AISettingsSection()
        SwiftUI.Section("Network definitions") {
            TextField("Internal networks (CIDR, comma separated)", text: Binding(get: { d.wrappedValue.internalNetworks.joined(separator: ", ") },
                                                                                  set: { d.wrappedValue.internalNetworks = $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }))
            TextField("Trusted DNS resolvers (comma separated)", text: Binding(get: { d.wrappedValue.trustedResolvers.joined(separator: ", ") },
                                                                                set: { d.wrappedValue.trustedResolvers = $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }))
            TextField("Accept telemetry only from (addresses, optional)", text: Binding(get: { d.wrappedValue.allowedExporterAddresses.joined(separator: ", ") },
                                                                                        set: { d.wrappedValue.allowedExporterAddresses = $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }))
        }
        SwiftUI.Section("GeoIP (optional, offline)") {
            HStack {
                Text("City database").frame(width: 120, alignment: .leading)
                Text(d.wrappedValue.geoIP.cityDatabasePath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "none").foregroundStyle(.secondary)
                Button("Import .mmdb…") { importMMDB { d.wrappedValue.geoIP.cityDatabasePath = $0 } }
                if d.wrappedValue.geoIP.cityDatabasePath != nil { Button("Remove") { d.wrappedValue.geoIP.cityDatabasePath = nil } }
            }
            HStack {
                Text("ASN database").frame(width: 120, alignment: .leading)
                Text(d.wrappedValue.geoIP.asnDatabasePath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "none").foregroundStyle(.secondary)
                Button("Import .mmdb…") { importMMDB { d.wrappedValue.geoIP.asnDatabasePath = $0 } }
                if d.wrappedValue.geoIP.asnDatabasePath != nil { Button("Remove") { d.wrappedValue.geoIP.asnDatabasePath = nil } }
            }
            Text("MaxMind GeoLite2 City/ASN files (or any MMDB) are read locally; nothing is looked up online. Files are copied into the application support folder.").font(.caption).foregroundStyle(.secondary)
        }
        SwiftUI.Section("Expected countries and networks") {
            ExpectationsEditor()
        }
        SwiftUI.Section("Privacy") {
            Toggle("Allow optional external lookups (off: nothing leaves this Mac)", isOn: d.privacy.externalLookupsEnabled)
            Toggle("Show native notifications for alerts and collector problems", isOn: d.notificationsEnabled)
            Toggle("Verbose diagnostic logging", isOn: d.diagnosticsVerbose)
        }
        SwiftUI.Section {
            HStack {
                Button("Apply") { Task { await applyWithPreview(d.wrappedValue) } }.keyboardShortcut(.defaultAction)
                Button("Revert") { draft = model.configuration; errors = [] }
                if saved { Text("Applied").foregroundStyle(.green).font(.caption) }
                Spacer()
            }
            ForEach(errors, id: \.self) { Text($0).foregroundStyle(.red).font(.caption) }
        }
        .sheet(item: Binding(get: { preview.map { PreviewBox(reply: $0) } }, set: { if $0 == nil { preview = nil } })) { box in
            ShrinkPreviewSheet(reply: box.reply,
                               confirm: { Task { if let c = pendingShrink { errors = await model.apply(c); saved = errors.isEmpty }; preview = nil; pendingShrink = nil } },
                               cancel: { preview = nil; pendingShrink = nil })
        }
    }

    /// Shrinking the budget shows exactly what retention would remove before anything is applied.
    private func applyWithPreview(_ config: CollectorConfiguration) async {
        if config.budgetBytes < model.configuration.budgetBytes, model.connectionState == .connected {
            do {
                let reply = try await model.client.request(RetentionPreviewRequest(budgetBytes: config.budgetBytes), timeout: .seconds(60))
                if !reply.steps.isEmpty { pendingShrink = config; preview = reply; return }
            } catch { errors = ["Could not preview retention: \(error.localizedDescription)"]; return }
        }
        errors = await model.apply(config); saved = errors.isEmpty
    }

    private func importMMDB(_ set: @escaping (String) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.data]
        panel.prompt = "Import"
        panel.message = "Choose a MaxMind DB (.mmdb) file."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let dir = URL(fileURLWithPath: NSHomeDirectory()).appending(path: "Library/Application Support/\(Branding.productName)/GeoIP")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let dst = dir.appending(path: url.lastPathComponent)
            if FileManager.default.fileExists(atPath: dst.path) { try FileManager.default.removeItem(at: dst) }
            try FileManager.default.copyItem(at: url, to: dst)
            set(dst.path)
        } catch { errors = ["GeoIP import failed: \(error.localizedDescription)"] }
    }

    private func chooseFolder(_ d: Binding<CollectorConfiguration>) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Use Folder"
        panel.message = "Choose where \(Branding.productName) stores telemetry. An encrypted volume is recommended."
        if panel.runModal() == .OK, let url = panel.url {
            d.wrappedValue.storageRoot = url.appending(path: "\(Branding.productName) Store").path
            if let bookmark = try? url.bookmarkData(options: .withSecurityScope, includingResourceValuesForKeys: nil, relativeTo: nil) {
                UserDefaults.standard.set(bookmark, forKey: "storageRootBookmark")
            }
        }
    }
}


struct PreviewBox: Identifiable { let id = UUID(); let reply: RetentionPreviewRequest.Reply }

struct ShrinkPreviewSheet: View {
    let reply: RetentionPreviewRequest.Reply
    let confirm: () -> Void
    let cancel: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Reducing the budget will delete data", systemImage: reply.removesRecentData ? "exclamationmark.triangle.fill" : "info.circle").font(.headline)
            Text("New budget \(Format.bytes(reply.budgetBytes)); usage \(Format.bytes(reply.usageBefore)) → about \(Format.bytes(reply.usageAfter)). Rollups, alerts, annotations and daily summaries are kept.")
                .font(.callout)
            ForEach(reply.steps, id: \.stage) { st in
                HStack(alignment: .top) {
                    Text("Stage \(st.stage)").font(.caption.bold()).frame(width: 60, alignment: .leading)
                    VStack(alignment: .leading) {
                        Text(st.description).font(.callout)
                        Text("frees \(Format.bytes(st.bytesFreed))\(st.segments > 0 ? " · \(st.segments) segments" : "")\(st.oldestSurvivingFlow.map { " · oldest flows kept from \(Format.time($0))" } ?? "")")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if reply.removesRecentData {
                Text("Data from the last 24 hours would be removed.").font(.callout).foregroundStyle(.red)
            }
            HStack { Spacer(); Button("Cancel", action: cancel).keyboardShortcut(.cancelAction); Button("Delete and apply", role: .destructive, action: confirm) }
        }
        .padding(20).frame(width: 520)
    }
}


/// Ask AI provider connection: base URL, API key (stored in the Keychain), and model, with an
/// optional fetch of the provider's available models. Supports OpenAI- and Anthropic-compatible APIs.
struct AISettingsSection: View {
    @Environment(AISettings.self) private var settings
    @Environment(AIService.self) private var ai
    @State private var models: [String] = []
    @State private var fetching = false
    @State private var fetchError: String?
    @State private var saved = false

    var body: some View {
        @Bindable var settings = settings
        SwiftUI.Section("Ask AI") {
            Picker("Provider", selection: $settings.provider) {
                ForEach(AISettings.Provider.allCases) { Text($0.label).tag($0) }
            }
            .onChange(of: settings.provider) { _, _ in settings.applyProviderDefaults(); models = []; markDirty() }

            TextField("Base URL", text: $settings.baseURL)
                .onChange(of: settings.baseURL) { _, _ in markDirty() }
            if settings.normalizedBaseURL == nil, !settings.baseURL.isEmpty {
                Text("Enter a valid http(s) URL, e.g. \(settings.provider.defaultBaseURL)").font(.caption).foregroundStyle(.red)
            }

            SecureField("API key", text: $settings.apiKey)
                .onChange(of: settings.apiKey) { _, _ in markDirty() }

            HStack {
                TextField("Model", text: $settings.model)
                    .onChange(of: settings.model) { _, _ in markDirty() }
                if !models.isEmpty {
                    Menu {
                        ForEach(models, id: \.self) { m in Button(m) { settings.model = m; save() } }
                    } label: { Image(systemName: "chevron.down.circle") }
                    .menuStyle(.borderlessButton).frame(width: 28)
                }
                Button { Task { await fetchModels() } } label: {
                    if fetching { ProgressView().controlSize(.small) } else { Text("Fetch") }
                }
                .disabled(fetching || settings.apiKey.isEmpty || settings.normalizedBaseURL == nil)
            }
            if let fetchError { Text(fetchError).font(.caption).foregroundStyle(.red) }

            VStack(alignment: .leading) {
                HStack {
                    Text("Temperature").frame(width: 120, alignment: .leading)
                    Slider(value: $settings.temperature, in: 0...1, step: 0.1) { _ in save() }
                    Text(settings.temperature.formatted(.number.precision(.fractionLength(1)))).monospacedDigit().frame(width: 32)
                }
                Text("Lower is more focused and factual; higher is more exploratory. 0.2 is a good default for troubleshooting.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            HStack {
                Button("Save") { save() }.keyboardShortcut(.defaultAction)
                if saved { Text("Saved").foregroundStyle(.green).font(.caption) }
                Spacer()
                Text("The API key is stored in your macOS Keychain. Requests go directly to the URL above.")
                    .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.trailing)
            }
        }
    }

    private func markDirty() { saved = false }

    private func save() {
        settings.save()
        saved = true
        fetchError = nil
    }

    private func fetchModels() async {
        fetching = true; fetchError = nil
        defer { fetching = false }
        // Persist the key first so the fetch uses what's on screen.
        settings.save()
        do {
            models = try await ai.fetchModels()
            if models.isEmpty { fetchError = "The provider returned no models." }
        } catch {
            fetchError = (error as? AIError)?.errorDescription ?? error.localizedDescription
        }
    }
}


/// Global expectations (countries, ASNs, destinations, VLAN pairs) and active suppressions, editable in place.
struct ExpectationsEditor: View {
    @Environment(AppModel.self) private var model
    @State private var expectations: [[String: String]] = []
    @State private var suppressions: [Suppression] = []
    @State private var kind = "country"
    @State private var value = ""
    @State private var error: String?
    private var security: SecurityClient { SecurityClient(client: model.client) }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Picker("", selection: $kind) { Text("Country (ISO code)").tag("country"); Text("ASN").tag("asn"); Text("Destination IP").tag("destination"); Text("VLAN pair (a>b)").tag("vlan-pair"); Text("Resolver").tag("resolver") }.frame(width: 170).labelsHidden()
                TextField("value, e.g. US or 15169", text: $value).textFieldStyle(.roundedBorder)
                Button("Add expected") { Task { do { try await security.addExpectation(scopeType: "global", scopeValue: "*", kind: kind, value: value.uppercased()); value = ""; await load() } catch { self.error = error.localizedDescription } } }.disabled(value.isEmpty)
            }
            ForEach(expectations, id: \.["id"]) { e in
                HStack {
                    Text("\(e["scopeType"] == "global" ? "Everyone" : "Client #\(e["scopeValue"] ?? "")") · \(e["kind"] ?? "") \(e["value"] ?? "")").font(.callout)
                    if let n = e["note"], !n.isEmpty { Text(n).font(.caption).foregroundStyle(.secondary) }
                    Spacer()
                    Button("Remove") { Task { try? await security.removeExpectation(Int64(e["id"] ?? "") ?? 0); await load() } }.controlSize(.small)
                }
            }
            if !suppressions.isEmpty {
                Text("Suppressions").font(.caption.bold()).padding(.top, 4)
                ForEach(suppressions) { s in
                    HStack {
                        Text(describe(s)).font(.callout)
                        Spacer()
                        Button("Remove") { Task { _ = try? await security.removeSuppression(s.id); await load() } }.controlSize(.small)
                    }
                }
            }
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
        }
        .task { await load() }
    }

    private func describe(_ s: Suppression) -> String {
        var parts = [s.ruleName == "*" ? "any rule" : s.ruleName]
        if let c = s.clientID { parts.append("client #\(c)") }
        if let d = s.destination { parts.append("→ \(d)") }
        if let p = s.port { parts.append("port \(p)") }
        if let a = s.asn { parts.append("AS\(a)") }
        if let c = s.country { parts.append(c) }
        if let a = s.startHour, let b = s.endHour { parts.append("\(a):00–\(b):00") }
        if let e = s.expiresAt { parts.append("until \(Format.time(e))") }
        if let r = s.reason { parts.append("(\(r))") }
        return parts.joined(separator: " ")
    }
    private func load() async {
        do { expectations = try await security.expectations(); suppressions = try await security.suppressions(); error = nil }
        catch { self.error = "Collector not reachable: \(error.localizedDescription)" }
    }
}
