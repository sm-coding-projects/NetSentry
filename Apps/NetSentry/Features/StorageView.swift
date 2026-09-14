import SwiftUI
import Charts
import NetSentryCore
import NetSentryIPC

struct StorageView: View {
    @Environment(AppModel.self) private var model
    @State private var summary: StorageSummary?
    @State private var verifying = false
    @State private var verifyResult: [String]?
    @State private var running = false
    @State private var error: String?
    @State private var message: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let s = summary ?? model.health?.storage {
                    budgetHeader(s)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 190), spacing: 12)], spacing: 12) {
                        StatCard(title: "Physical usage", value: Format.bytes(s.usedBytes), detail: "of \(Format.bytes(s.budgetBytes)) budget", systemImage: "internaldrive", tint: s.usedBytes > s.budgetBytes ? .red : .accentColor)
                        StatCard(title: "Free on volume", value: Format.bytes(s.freeBytesOnVolume), detail: "safety threshold \(Format.bytes(s.safetyThresholdBytes))", systemImage: "externaldrive", tint: s.freeBytesOnVolume < s.safetyThresholdBytes ? .red : .green)
                        StatCard(title: "Estimated retention", value: s.estimatedRetentionDays.map { String(format: "%.1f days", $0) } ?? "measuring…", detail: "detailed flows and events at the current rate", systemImage: "calendar")
                        StatCard(title: "Oldest record", value: s.oldestRecord.map { Format.relative($0) } ?? "—", detail: s.oldestRecord.map { Format.time($0) }, systemImage: "clock.arrow.circlepath")
                        StatCard(title: "Newest record", value: s.newestRecord.map { Format.relative($0) } ?? "—", detail: s.newestRecord.map { Format.time($0) }, systemImage: "clock")
                        StatCard(title: "Segments", value: "\(s.segmentCount)", detail: s.integrityIssues == 0 ? "no integrity issues" : "\(s.integrityIssues) integrity issues", systemImage: "square.stack.3d.up", tint: s.integrityIssues == 0 ? .secondary : .orange)
                        StatCard(title: "Compaction", value: s.compactionInProgress ? "Running" : "Idle", detail: "minute → hour → day segments", systemImage: "arrow.down.right.and.arrow.up.left")
                        StatCard(title: "Ingestion", value: s.ingestionPaused ? "Paused" : "Active", detail: s.ingestionPaused ? "disk below safety threshold" : "writing minute segments", systemImage: s.ingestionPaused ? "pause.circle" : "record.circle", tint: s.ingestionPaused ? .red : .green)
                    }
                    categories(s)
                    actions
                } else {
                    CollectorUnavailableView()
                }
            }
            .padding(20)
        }
        .task { await refresh() }
        .onChange(of: model.health?.generatedAt) { _, _ in if summary == nil { summary = model.health?.storage } }
    }

    private func budgetHeader(_ s: StorageSummary) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Storage budget").font(.headline)
                Spacer()
                Text("\(Format.bytes(s.usedBytes)) of \(Format.bytes(s.budgetBytes))").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
            }
            ProgressView(value: min(1, Double(s.usedBytes) / Double(max(s.budgetBytes, 1))))
                .tint(s.usedBytes > s.budgetBytes ? .red : (Double(s.usedBytes) / Double(max(s.budgetBytes, 1)) > 0.9 ? .orange : .accentColor))
            Text("The budget is a ceiling, not a preallocation. Retention removes captures, raw syslog copies and the oldest detailed segments in that order; rollups, alerts and annotations are kept. Location: \(s.root)")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func categories(_ s: StorageSummary) -> some View {
        GroupBox("Usage by category") {
            let order = ["flows", "events", "raw", "metadata", "other"]
            let labels = ["flows": "Flow records", "events": "Parsed syslog", "raw": "Raw syslog & captures", "metadata": "Metadata, rollups, alerts", "other": "Temp, exports, GeoIP"]
            let rows = order.compactMap { k in s.usedByCategory[k].map { (k, $0) } }
            VStack(alignment: .leading, spacing: 8) {
                Chart(rows, id: \.0) { item in
                    BarMark(x: .value("Bytes", item.1), y: .value("Category", labels[item.0] ?? item.0))
                        .foregroundStyle(by: .value("Category", labels[item.0] ?? item.0))
                }
                .chartXAxis { AxisMarks { v in AxisValueLabel { if let b = v.as(Int64.self) { Text(Format.bytes(b)) } } } }
                .chartLegend(.hidden)
                .frame(height: CGFloat(40 + rows.count * 26))
                ForEach(rows, id: \.0) { k, v in
                    HStack { Text(labels[k] ?? k); Spacer(); Text(Format.bytes(v)).monospacedDigit() }.font(.callout)
                }
                let alloc = model.configuration.allocation
                Text("Allocation targets: flows \(Int(alloc.flows * 100)) %, events \(Int(alloc.events * 100)) %, raw \(Int(alloc.raw * 100)) %, metadata \(Int(alloc.metadata * 100)) %, reserve \(Int(alloc.reserve * 100)) %.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var actions: some View {
        GroupBox("Maintenance") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Button("Refresh") { Task { await refresh() } }
                    Button("Flush now") { Task { await run { try await model.client.request(StorageFlushRequest()) } } }.disabled(running)
                    Button("Run retention now") { Task { await run { try await model.client.request(RetentionRunRequest()) } } }.disabled(running)
                    Button("Back up manifest…") { Task { await backup() } }.disabled(running)
                    if let message { Text(message).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle) }
                    Button(verifying ? "Verifying…" : "Verify all segments") { Task { await verify() } }.disabled(verifying)
                    Spacer()
                }
                if let r = verifyResult {
                    Text(r.isEmpty ? "All segments verified: files present, checksums and row counts match." : r.joined(separator: "\n"))
                        .font(.caption).foregroundStyle(r.isEmpty ? .green : .orange)
                }
                if let error { Text(error).font(.caption).foregroundStyle(.red) }
                Text("Segments are immutable Parquet files finalized atomically; interrupted writes are removed at startup and orphaned files are quarantined under tmp/.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func backup() async {
        do {
            let r = try await model.client.request(StorageBackupRequest(), timeout: .seconds(120))
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: r.path)])
            message = "Backup written: \(r.path) (\(Format.bytes(r.bytes)))"
        } catch { message = "Backup failed: \(error.localizedDescription)" }
    }

    private func refresh() async {
        do { summary = try await model.client.request(StorageStatusRequest()); error = nil } catch { self.error = error.localizedDescription }
    }

    private func run(_ op: @escaping () async throws -> StorageSummary) async {
        running = true; defer { running = false }
        do { summary = try await op(); error = nil } catch { self.error = error.localizedDescription }
    }

    private func verify() async {
        verifying = true; defer { verifying = false }
        do { verifyResult = try await model.client.request(SegmentsVerifyRequest(), timeout: .seconds(600)).issues } catch { self.error = error.localizedDescription }
    }
}
