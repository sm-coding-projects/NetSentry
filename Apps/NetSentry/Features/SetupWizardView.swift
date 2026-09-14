import SwiftUI
import NetSentryCore
import NetSentryIPC

/// First-run wizard: storage location and budget → gateway configuration → background collector → live traffic
/// validation → done. Every step applies real configuration; nothing is simulated.
struct SetupWizardView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var step = 0
    @State private var draft: CollectorConfiguration
    @State private var errors: [String] = []
    @State private var testing = false
    @State private var ipfixResult: ListenerTestRequest.Reply?
    @State private var syslogResult: ListenerTestRequest.Reply?
    @State private var applying = false

    init(configuration: CollectorConfiguration) { _draft = State(initialValue: configuration) }

    private let steps = ["Welcome", "Storage", "Gateway", "Collector", "Validate", "Done"]

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                ForEach(steps.indices, id: \.self) { i in
                    Text(steps[i]).font(.caption).fontWeight(i == step ? .bold : .regular).foregroundStyle(i <= step ? .primary : .tertiary)
                    if i < steps.count - 1 { Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary).accessibilityHidden(true) }
                }
                Spacer()
            }.padding(14)
            Divider()
            ScrollView { content.padding(20).frame(maxWidth: .infinity, alignment: .leading) }
            Divider()
            HStack {
                ForEach(errors, id: \.self) { Text($0).font(.caption).foregroundStyle(.red) }
                Spacer()
                if step > 0 && step < steps.count - 1 { Button("Back") { step -= 1 } }
                if step < steps.count - 1 {
                    Button(step == 0 ? "Get started" : "Continue") { Task { await advance() } }.keyboardShortcut(.defaultAction).disabled(applying)
                } else {
                    Button("Open dashboard") { Task { await finish() } }.keyboardShortcut(.defaultAction)
                }
            }.padding(14)
        }
        .frame(width: 680, height: 520)
    }

    @ViewBuilder private var content: some View {
        switch step {
        case 0:
            VStack(alignment: .leading, spacing: 12) {
                Text("Welcome to \(Branding.productName)").font(.title)
                Text("\(Branding.productName) receives NetFlow (IPFIX) and syslog from your UniFi Cloud Gateway Fiber, stores it on this Mac and explains what it sees. Nothing leaves this computer.")
                Text("This setup takes about five minutes: choose where to store data, point the gateway at this Mac, enable the background collector, then confirm traffic arrives.")
                Label("Your Mac needs a fixed address on the LAN. If it gets its address from DHCP, reserve it in UniFi (Client → Settings → Fixed IP) so the gateway keeps sending to the right place.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
            }
        case 1:
            VStack(alignment: .leading, spacing: 12) {
                Text("Storage").font(.title2)
                LabeledContent("Folder") { HStack { Text(draft.storageRoot).lineLimit(1).truncationMode(.middle); Button("Choose…") { chooseFolder() } } }
                Text("Choose an encrypted volume (FileVault or an encrypted APFS volume). The folder is created with owner-only permissions.").font(.caption).foregroundStyle(.secondary)
                Picker("Budget", selection: Binding(get: { Double(draft.budgetBytes) / 1e9 }, set: { draft.budgetBytes = StorageBudget.clamp(Int64($0 * 1e9)) })) {
                    ForEach([5.0, 10, 25, 50, 100, 250, 500], id: \.self) { Text("\(Int($0)) GB").tag($0) }
                }.pickerStyle(.segmented)
                Text("The budget is a ceiling: old detailed data is thinned to rollups and then deleted to stay under it. Free space on the volume is also protected; collection pauses if it drops below the safety threshold.").font(.caption).foregroundStyle(.secondary)
                if let free = try? URL(fileURLWithPath: draft.storageRoot).deletingLastPathComponent().resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]).volumeAvailableCapacityForImportantUsage {
                    Text("Free on that volume now: \(Format.bytes(free))").font(.caption)
                }
            }
        case 2:
            VStack(alignment: .leading, spacing: 12) {
                Text("Configure the gateway").font(.title2)
                Text("In the UniFi Network application:").font(.callout)
                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("1. Settings → Insights (or Traffic Logging) → NetFlow: enable, set the collector to this Mac and port **\(ipfixPort)**, version **IPFIX (v10)**; keep the sampling rate the gateway proposes.")
                        Text("2. Settings → System → Remote Logging (or Control Plane → Integrations → Syslog): enable, host = this Mac, port **\(syslogPort)**, protocol UDP. Enable the firewall, DHCP, IDS/IPS and admin activity categories where offered.")
                        Text("3. Make sure the gateway's own firewall allows traffic from the gateway to this Mac on those UDP ports (LAN → LAN is allowed by default).")
                    }.font(.callout).frame(maxWidth: .infinity, alignment: .leading)
                }
                LabeledContent("This Mac's addresses") { Text(NetworkInterfaces.list().filter(\.isUp).flatMap { i in i.addresses.map { "\($0) (\(i.name))" } }.joined(separator: ", ")).textSelection(.enabled) }
                Text("Ports below 1024 (the syslog default 514) cannot be used because the collector runs as your user; 5514 is the default here.").font(.caption).foregroundStyle(.secondary)
                Text("Full guide: docs/unifi-configuration.md").font(.caption).foregroundStyle(.secondary)
            }
        case 3:
            VStack(alignment: .leading, spacing: 12) {
                Text("Background collector").font(.title2)
                Text("The collector is a separate login item that keeps receiving while this window is closed and restarts after a crash or a reboot. macOS will show it under System Settings → General → Login Items.")
                LabeledContent("Status", value: model.agentStatus)
                LabeledContent("Connection", value: model.connectionState == .connected ? "connected" : "not connected")
                Toggle("Collect telemetry in the background (registers the login item)", isOn: $draft.collectionEnabled)
                Toggle("Show notifications for alerts", isOn: $draft.notificationsEnabled)
                if model.agentStatus.contains("approval") { Text("macOS is waiting for your approval in System Settings → Login Items.").foregroundStyle(.orange) ; Button("Open Login Items…") { model.manager.openLoginItemsSettings() } }
            }
        case 4:
            VStack(alignment: .leading, spacing: 12) {
                Text("Validate traffic").font(.title2)
                Text("Listens for 15 seconds on both channels and reports what arrived. IPFIX templates typically arrive within a few minutes of enabling NetFlow; syslog is immediate when something happens on the network.")
                HStack { Button(testing ? "Listening…" : "Run test") { Task { await runTests() } }.disabled(testing || model.connectionState != .connected); if testing { ProgressView().controlSize(.small) } }
                if let r = ipfixResult { resultBox("IPFIX on UDP \(ipfixPort)", r, hint: r.packets == 0 ? "Nothing arrived. Check the NetFlow target address/port and that the gateway can reach this Mac." : (r.templatesSeen == 0 && r.recordsDecoded == 0 ? "Datagrams arrived but no template yet; records are buffered until the gateway resends templates (a few minutes)." : "Flows decode correctly.")) }
                if let r = syslogResult { resultBox("Syslog on UDP \(syslogPort)", r, hint: r.packets == 0 ? "No syslog yet. Confirm Remote Logging points at port \(syslogPort) (not 514) and trigger an event, e.g. connect a device." : "Events arrive.") }
                if model.connectionState != .connected { Text("The collector is not running; go back and enable it, or approve it in Login Items.").foregroundStyle(.orange) }
                Text("You can continue without traffic and re-run this test from Collector Health.").font(.caption).foregroundStyle(.secondary)
            }
        default:
            VStack(alignment: .leading, spacing: 12) {
                Text("Ready").font(.title2)
                Text("\(Branding.productName) is collecting. The Overview fills in as data arrives; detections start after a learning period so the first days build baselines rather than alerts.")
                Text("Later: import a MaxMind GeoIP database in Settings for country and network names; name your devices in Clients; mark expected destinations to keep alerts quiet.")
            }
        }
    }

    private var ipfixPort: String { draft.listeners.filter { $0.kind == .ipfix && $0.enabled }.map { "\($0.port)" }.joined(separator: " or ") }
    private var syslogPort: String { draft.listeners.first { $0.kind == .syslog && $0.transport == .udp && $0.enabled }.map { "\($0.port)" } ?? "5514" }

    @ViewBuilder private func resultBox(_ title: String, _ r: ListenerTestRequest.Reply, hint: String) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 3) {
                HStack { StatusBadge(text: r.listening ? "listening" : "not listening", kind: r.listening ? .ok : .error); Text("\(r.packets) packets, \(Format.bytes(Int64(r.bytes)))"); if r.kind == .ipfix { Text("· \(r.templatesSeen) templates, \(r.recordsDecoded) records") } else { Text("· \(r.recordsDecoded) events") } }
                if !r.sources.isEmpty { Text("From: \(r.sources.joined(separator: ", "))").font(.caption) }
                ForEach(r.errors, id: \.self) { Text($0).font(.caption).foregroundStyle(.red) }
                Text(hint).font(.caption).foregroundStyle(r.packets == 0 ? .orange : .secondary)
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func advance() async {
        errors = []
        switch step {
        case 1, 2:
            applying = true; defer { applying = false }
            errors = await model.apply(draft)
            if !errors.isEmpty { return }
        case 3:
            applying = true; defer { applying = false }
            errors = await model.apply(draft)
            if !errors.isEmpty { return }
            await model.setCollectorEnabled(draft.collectionEnabled)
            if let e = model.lastError { errors = [e] }
            try? await Task.sleep(for: .seconds(2))
            await model.refresh()
        default: break
        }
        step += 1
    }

    private func runTests() async {
        testing = true; defer { testing = false }
        async let a = try? model.client.request(ListenerTestRequest(kind: .ipfix, seconds: 15), timeout: .seconds(40))
        async let b = try? model.client.request(ListenerTestRequest(kind: .syslog, seconds: 15), timeout: .seconds(40))
        ipfixResult = await a; syslogResult = await b
    }

    private func finish() async {
        var c = model.configuration
        c.setupCompleted = true
        errors = await model.apply(c)
        if errors.isEmpty { dismiss() }
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.canCreateDirectories = true
        panel.prompt = "Use Folder"; panel.message = "Choose where \(Branding.productName) stores telemetry. An encrypted volume is recommended."
        if panel.runModal() == .OK, let url = panel.url { draft.storageRoot = url.appending(path: "\(Branding.productName) Store").path }
    }
}
