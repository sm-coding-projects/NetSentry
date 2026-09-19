import SwiftUI
import NetSentryCore

enum Section: String, CaseIterable, Identifiable, Hashable {
    case overview, liveActivity, clients, flows, events, security, investigation, askAI, storage, collectorHealth, settings
    var id: String { rawValue }
    var title: String {
        switch self {
        case .overview: "Overview"
        case .liveActivity: "Live Activity"
        case .clients: "Clients"
        case .flows: "Flows"
        case .events: "Events"
        case .security: "Security"
        case .investigation: "Investigation"
        case .askAI: "Ask AI"
        case .storage: "Storage"
        case .collectorHealth: "Collector Health"
        case .settings: "Settings"
        }
    }
    var symbol: String {
        switch self {
        case .overview: "gauge.with.dots.needle.33percent"
        case .liveActivity: "waveform.path.ecg"
        case .clients: "desktopcomputer"
        case .flows: "arrow.left.arrow.right"
        case .events: "list.bullet.rectangle"
        case .security: "shield.lefthalf.filled"
        case .investigation: "magnifyingglass"
        case .askAI: "sparkles"
        case .storage: "internaldrive"
        case .collectorHealth: "heart.text.square"
        case .settings: "gearshape"
        }
    }
    /// Phase in which the full view ships; nil when already available.
    var availableInPhase: Int? {
        switch self {
        case .overview, .collectorHealth, .settings, .liveActivity, .storage, .clients, .flows, .events, .security, .investigation, .askAI: nil
        }
    }
}

struct MainView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: Section? = .overview

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                SwiftUI.Section("Monitor") {
                    row(.overview); row(.liveActivity)
                }
                SwiftUI.Section("Investigate") {
                    row(.clients); row(.flows); row(.events); row(.security); row(.investigation); row(.askAI)
                }
                SwiftUI.Section("System") {
                    row(.storage); row(.collectorHealth); row(.settings)
                }
            }
            .navigationSplitViewColumnWidth(220)
            .safeAreaInset(edge: .bottom) { ConnectionFooter() }
        } detail: {
            detail(for: selection ?? .overview)
                .navigationTitle(selection?.title ?? Branding.productName)
        }
        .overlay(alignment: .top) {
            if model.health?.demoWorkspace == true { DemoBanner() }
        }
        .onChange(of: model.requestedSection) { _, s in if let s { selection = s; model.requestedSection = nil } }
        .sheet(isPresented: Binding(get: { model.showSetupWizard }, set: { model.showSetupWizard = $0 })) { SetupWizardView(configuration: model.configuration).environment(model) }
    }

    private func row(_ s: Section) -> some View {
        Label(s.title, systemImage: s.symbol).tag(s)
            .accessibilityLabel(s.title)
    }

    @ViewBuilder
    private func detail(for s: Section) -> some View {
        switch s {
        case .overview: OverviewView()
        case .liveActivity: LiveActivityView()
        case .storage: StorageView()
        case .clients: ClientsView()
        case .flows: FlowsView()
        case .events: EventsView()
        case .security: SecurityView()
        case .investigation: InvestigationView()
        case .askAI: AskAIView()
        case .collectorHealth: CollectorHealthView()
        case .settings: SettingsView()
        default: PhasePlaceholderView(section: s)
        }
    }
}

struct ConnectionFooter: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(text).font(.caption).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Collector \(text)")
    }
    private var color: Color {
        switch model.connectionState { case .connected: .green; case .connecting: .yellow; case .disconnected: .red }
    }
    private var text: String {
        switch model.connectionState {
        case .connected: "Collector connected"
        case .connecting: "Connecting…"
        case .disconnected: model.configuration.collectionEnabled ? "Collector not running" : "Collector disabled"
        }
    }
}

struct DemoBanner: View {
    var body: some View {
        Text("SIMULATED DATA — demo workspace")
            .font(.caption.bold()).padding(.horizontal, 12).padding(.vertical, 4)
            .background(.orange, in: Capsule()).foregroundStyle(.black).padding(.top, 6)
            .accessibilityLabel("Simulated data. Demo workspace is active.")
    }
}

struct PhasePlaceholderView: View {
    let section: Section
    var body: some View {
        ContentUnavailableView {
            Label(section.title, systemImage: section.symbol)
        } description: {
            Text("This view ships in Phase \(section.availableInPhase ?? 0). Nothing here is simulated; the collector is recording real health data now.")
        }
    }
}
