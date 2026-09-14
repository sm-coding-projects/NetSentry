import SwiftUI
import NetSentryCore
import NetSentryIPC

struct CollectorHealthView: View {
    @Environment(AppModel.self) private var model
    @State private var exporting = false
    @State private var includeTelemetry = false
    @State private var exportMessage: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let h = model.health {
                    header(h)
                    listeners(h)
                    exporters(h)
                    counters(h)
                    queues(h)
                    gaps(h)
                    if !h.warnings.isEmpty { WarningsList(warnings: h.warnings) }
                } else {
                    CollectorUnavailableView()
                }
            }
            .padding(20)
        }
    }

    private func header(_ h: HealthSnapshot) -> some View {
        GroupBox("Service") {
            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 6) {
                GridRow { Text("Version").foregroundStyle(.secondary); Text("\(h.collectorVersion) (\(h.collectorBuild))") }
                GridRow { Text("Process").foregroundStyle(.secondary); Text("pid \(h.pid), started \(Format.time(h.startedAt))") }
                GridRow { Text("Login item").foregroundStyle(.secondary); Text(model.agentStatus) }
                GridRow { Text("Snapshot").foregroundStyle(.secondary); Text(Format.time(h.generatedAt)) }
            }
            .font(.callout).frame(maxWidth: .infinity, alignment: .leading)
            Divider().padding(.vertical, 4)
            HStack {
                Button(exporting ? "Exporting…" : "Export diagnostics…") { Task { await exportDiagnostics() } }.disabled(exporting)
                Toggle("Include newest raw capture and a manifest backup", isOn: $includeTelemetry).toggleStyle(.checkbox)
                if exporting { ProgressView().controlSize(.small) }
                Spacer()
            }
            Text("A zip with health, configuration (secrets removed), storage status, verification, gaps, detection statistics, system facts and two hours of NetSentry log lines. Review it before sharing; addresses are not redacted.")
                .font(.caption).foregroundStyle(.secondary)
            if let exportMessage { Text(exportMessage).font(.caption).textSelection(.enabled) }
        }
    }

    private func exportDiagnostics() async {
        exporting = true; defer { exporting = false }
        do {
            let r = try await model.client.request(DiagnosticsExportRequest(includeTelemetry: includeTelemetry), timeout: .seconds(300))
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: r.path)])
            exportMessage = "Written to \(r.path)"
        } catch { exportMessage = "Export failed: \(error.localizedDescription)" }
    }

    private func listeners(_ h: HealthSnapshot) -> some View {
        GroupBox("Listeners") {
            Table(h.listeners) {
                TableColumn("Kind") { Text($0.kind.label) }.width(60)
                TableColumn("Transport") { Text($0.transport.label) }.width(70)
                TableColumn("Port") { Text("\($0.port)") }.width(50)
                TableColumn("Interface") { Text($0.interface ?? "all") }.width(70)
                TableColumn("State") { l in StatusBadge(text: l.state.label, kind: badge(l.state)) }
                TableColumn("Datagrams") { Text(Format.count($0.datagramsReceived)) }.width(90)
                TableColumn("Bytes") { Text(Format.bytes($0.bytesReceived)) }.width(80)
                TableColumn("Last packet") { Text(Format.relative($0.lastPacketAt)) }
                TableColumn("Last source") { Text($0.lastSource ?? "—") }
            }
            .frame(minHeight: 44 + CGFloat(max(1, h.listeners.count)) * 26)
        }
    }

    private func badge(_ s: ListenerState) -> StatusBadge.Kind {
        switch s { case .listening: .ok; case .starting: .warning; case .failed: .error; case .stopped, .disabled: .neutral }
    }

    private func exporters(_ h: HealthSnapshot) -> some View {
        GroupBox("Exporters and observation domains") {
            if h.exporters.isEmpty {
                Text("No exporter identified yet. IPFIX exporters are registered once templates are decoded (Phase 2).")
                    .font(.callout).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Table(h.exporters) {
                    TableColumn("Kind") { Text($0.kind.label) }.width(60)
                    TableColumn("Exporter") { Text($0.key.description) }
                    TableColumn("Messages") { Text(Format.count($0.messages)) }
                    TableColumn("Records") { Text(Format.count($0.records)) }
                    TableColumn("Templates") { Text("\($0.templates)") }
                    TableColumn("Seq gaps") { Text(Format.count($0.sequenceGaps)) }
                    TableColumn("Pending") { Text("\($0.pendingUndecodable)") }
                    TableColumn("Skew") { e in Text(e.clockSkewMicroseconds.map { String(format: "%+.1f s", Double($0) / 1e6) } ?? "—") }
                    TableColumn("Last seen") { Text(Format.relative($0.lastSeen)) }
                }
                .frame(minHeight: 44 + CGFloat(h.exporters.count) * 26)
            }
        }
    }

    private func counters(_ h: HealthSnapshot) -> some View {
        GroupBox("Pipeline counters") {
            let c = h.counters
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), spacing: 10)], spacing: 10) {
                StatCard(title: "Received", value: Format.count(c.datagramsReceived), detail: Format.bytes(c.bytesReceived))
                StatCard(title: "Dropped (receive queue)", value: Format.count(c.receiveQueueDropped), tint: c.receiveQueueDropped > 0 ? .red : .secondary)
                StatCard(title: "Rejected", value: Format.count(c.rejected), detail: "not in allowed exporters")
                StatCard(title: "Flows decoded", value: Format.count(c.flowsDecoded))
                StatCard(title: "Events decoded", value: Format.count(c.eventsDecoded))
                StatCard(title: "Malformed", value: Format.count(c.malformed), tint: c.malformed > 0 ? .orange : .secondary)
                StatCard(title: "Missing template", value: Format.count(c.missingTemplate), detail: "\(Format.count(c.bufferedPendingTemplate)) buffered")
                StatCard(title: "Sequence gaps", value: Format.count(c.sequenceGaps))
                StatCard(title: "Parser failures", value: Format.count(c.parserFailures))
                StatCard(title: "Stored", value: Format.count(c.stored))
                StatCard(title: "Storage write failures", value: Format.count(c.storageWriteFailures), tint: c.storageWriteFailures > 0 ? .red : .secondary)
            }
        }
    }

    private func queues(_ h: HealthSnapshot) -> some View {
        GroupBox("Queues") {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(h.queues, id: \.name) { q in
                    HStack {
                        Text(q.name).frame(width: 90, alignment: .leading)
                        ProgressView(value: q.utilization).frame(maxWidth: 240)
                        Text("\(q.depth) / \(q.capacity)").monospacedDigit().frame(width: 110, alignment: .leading)
                        Text("high \(q.highWatermark) · dropped \(Format.count(q.dropped))").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("Queue \(q.name), \(Int(q.utilization * 100)) percent full, \(q.dropped) dropped")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func gaps(_ h: HealthSnapshot) -> some View {
        GroupBox("Open collection gaps") {
            if h.openGaps.isEmpty {
                Text("None. Gaps are recorded whenever collection is known to be incomplete and are never shown as “no activity”.")
                    .font(.callout).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                ForEach(h.openGaps) { g in
                    HStack {
                        Image(systemName: "rectangle.dashed").foregroundStyle(.orange).accessibilityLabel("Gap")
                        Text(g.kind.label).font(.callout.weight(.medium))
                        Text(g.reason).font(.callout).foregroundStyle(.secondary)
                        Spacer()
                        Text("since \(Format.relative(g.start))").font(.caption).foregroundStyle(.tertiary)
                    }
                }
            }
        }
    }
}
