import SwiftUI
import NetSentryCore

struct OverviewView: View {
    @Environment(AppModel.self) private var model
    @Environment(AnalyticsService.self) private var analytics
    @State private var loader = OverviewLoader()
    @State private var preset: RangePreset = .h1

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let h = model.health {
                    statusRow(h)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 12)], spacing: 12) {
                        StatCard(title: "Flows / s", value: Format.rate(h.rates.flowsPerSecond, unit: ""), detail: "\(Format.count(h.counters.flowsDecoded)) decoded", systemImage: "arrow.left.arrow.right")
                        StatCard(title: "Events / s", value: Format.rate(h.rates.eventsPerSecond, unit: ""), detail: "\(Format.count(h.counters.eventsDecoded)) parsed", systemImage: "list.bullet.rectangle")
                        StatCard(title: "Datagrams / s", value: Format.rate(h.rates.datagramsPerSecond, unit: ""), systemImage: "antenna.radiowaves.left.and.right")
                        StatCard(title: "Receive rate", value: Format.bytes(Int64(h.rates.bytesPerSecond)) + "/s", systemImage: "speedometer")
                        StatCard(title: "Datagrams received", value: Format.count(h.counters.datagramsReceived), detail: Format.bytes(h.counters.bytesReceived), systemImage: "tray.and.arrow.down")
                        StatCard(title: "Dropped at receive", value: Format.count(h.counters.receiveQueueDropped), systemImage: "exclamationmark.triangle", tint: h.counters.receiveQueueDropped > 0 ? .red : .secondary)
                        StatCard(title: "Open collection gaps", value: "\(h.openGaps.count)", detail: h.openGaps.first?.reason, systemImage: "rectangle.dashed", tint: h.openGaps.isEmpty ? .secondary : .orange)
                        if let s = h.storage {
                            StatCard(title: "Storage used", value: Format.bytes(s.usedBytes), detail: "budget \(Format.bytes(s.budgetBytes)) · free \(Format.bytes(s.freeBytesOnVolume))", systemImage: "internaldrive")
                        }
                    }
                    if !h.warnings.isEmpty { WarningsList(warnings: h.warnings) }
                }
                analyticsSection
            }
            .padding(20)
        }
        .task { reload() }
        .onChange(of: preset) { _, _ in reload() }
        .onChange(of: model.health?.storage?.newestRecord) { _, _ in if loader.data == nil { reload() } }
    }

    private func reload() {
        loader.load(analytics: analytics, root: URL(fileURLWithPath: model.storageRootPath), preset: preset,
                    origin: model.health?.demoWorkspace == true ? .simulated : .live)
    }

    @ViewBuilder
    private var analyticsSection: some View {
        HStack {
            Text("Historical").font(.headline)
            Picker("Range", selection: $preset) { ForEach(RangePreset.allCases) { Text($0.rawValue).tag($0) } }.frame(width: 130).labelsHidden()
            if loader.loading { ProgressView().controlSize(.small) }
            if let d = loader.data { Text("\(Format.duration(d.elapsed))").font(.caption).foregroundStyle(.tertiary) }
            Spacer()
            Button("Reload") { reload() }
        }
        if let err = loader.error {
            Text(err).font(.caption).foregroundStyle(.red)
        }
        if let d = loader.data {
            GroupBox("Traffic") {
                VStack(alignment: .leading, spacing: 6) {
                    if let t = d.totals {
                        Text("\(Format.bytes(t.bytes)) in \(Format.count(UInt64(t.flows))) flows · outbound \(Format.bytes(t.outboundBytes)) · inbound \(Format.bytes(t.inboundBytes))")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    TrafficChart(series: d.series, gaps: d.gaps, range: d.range)
                    if !d.gaps.isEmpty {
                        let kinds = d.gaps.reduce(into: [String]()) { acc, g in if !acc.contains(g.kind.label) { acc.append(g.kind.label) } }
                        Text("Shaded areas are collection gaps (\(d.gaps.count)): \(kinds.joined(separator: ", ")). They are never shown as zero traffic.").font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 380), spacing: 12)], spacing: 12) {
                TopList(title: "Top clients (outbound)", rows: d.topClients)
                TopList(title: "Top destinations (outbound)", rows: d.topDestinations)
                TopList(title: "Top ports", rows: d.topPorts) { "\($0)" }
                TopList(title: "Top countries (outbound)", rows: d.topCountries) { $0.isEmpty ? "unknown (no GeoIP)" : $0 }
                TopList(title: "Top organizations (ASN)", rows: d.topASNs) { $0.isEmpty ? "unknown (no GeoIP)" : $0 }
                GroupBox("Events") {
                    VStack(alignment: .leading, spacing: 4) {
                        let allowed = d.eventsByAction.first { $0.key == "1" }?.count ?? 0
                        let denied = d.eventsByAction.filter { ["2", "3", "4"].contains($0.key) }.reduce(0) { $0 + $1.count }
                        Text("Allowed \(allowed) · Denied/blocked \(denied)").font(.callout)
                        ForEach(d.eventsByType) { r in
                            HStack { Text(EventType(rawValue: UInt8(r.key) ?? 0)?.label ?? r.key); Spacer(); Text("\(r.count)").monospacedDigit() }.font(.callout)
                        }
                        if d.eventsByType.isEmpty { Text("No syslog events in range").font(.caption).foregroundStyle(.secondary) }
                        if !d.idsSignatures.isEmpty {
                            Divider()
                            Text("IDS/IPS").font(.caption.bold())
                            ForEach(d.idsSignatures.prefix(5)) { r in HStack { Text(r.key).lineLimit(1); Spacer(); Text("\(r.count)") }.font(.caption) }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            GroupBox("Coming in Phase 5") {
                Text("New external destinations, countries and ASNs, client baselines and active alerts appear with entity resolution and detections. Nothing here is a placeholder number.")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            }
        } else if !loader.loading {
            ContentUnavailableView("No historical data yet", systemImage: "chart.xyaxis.line", description: Text("Aggregates appear once the collector has written its first segment (about a minute after data starts arriving)."))
        }
    }

    private func statusRow(_ h: HealthSnapshot) -> some View {
        HStack(spacing: 12) {
            let listening = h.listeners.filter { $0.state == .listening }.count
            let failed = h.listeners.contains { if case .failed = $0.state { true } else { false } }
            StatusBadge(text: failed ? "Listener failure" : (listening > 0 ? "Collecting" : "Idle"), kind: failed ? .error : (listening > 0 ? .ok : .neutral))
            Text("\(listening) of \(h.listeners.count) listeners active · collector \(h.collectorVersion) (\(h.collectorBuild)) · up since \(Format.time(h.startedAt))")
                .font(.callout).foregroundStyle(.secondary)
            Spacer()
        }
    }
}

struct WarningsList: View {
    let warnings: [HealthWarning]
    var body: some View {
        GroupBox("Warnings") {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(warnings) { w in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: w.level == .critical ? "xmark.octagon.fill" : (w.level == .warning ? "exclamationmark.triangle.fill" : "info.circle.fill")).accessibilityHidden(true)
                            .foregroundStyle(w.level == .critical ? .red : (w.level == .warning ? .orange : .blue))
                        VStack(alignment: .leading) {
                            Text(w.title).font(.callout.weight(.medium))
                            Text(w.detail).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(Format.relative(w.since)).font(.caption2).foregroundStyle(.tertiary)
                    }
                    .accessibilityElement(children: .combine)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct CollectorUnavailableView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        ContentUnavailableView {
            Label("Collector not running", systemImage: "bolt.slash")
        } description: {
            Text(model.configuration.collectionEnabled
                 ? "The background collector is enabled but not reachable. Login item status: \(model.agentStatus)."
                 : "Enable the background collector in Settings to start receiving IPFIX and syslog.")
        } actions: {
            if !model.configuration.collectionEnabled {
                Button("Enable Collector") { Task { await model.setCollectorEnabled(true) } }.buttonStyle(.borderedProminent)
            } else {
                Button("Open Login Items Settings") { model.manager.openLoginItemsSettings() }
                Button("Retry") { Task { await model.refresh() } }
            }
        }
    }
}
