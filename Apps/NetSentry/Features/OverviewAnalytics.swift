import SwiftUI
import Charts
import NetSentryAnalytics
import NetSentryCore

/// Aggregates for the Overview, loaded together and cancellable as one unit.
struct OverviewData: Sendable {
    var range: TimeRange
    var series: [TimeBucket] = []
    var totals: TimeBucket?
    var topClients: [TopNRow] = []
    var topDestinations: [TopNRow] = []
    var topPorts: [TopNRow] = []
    var topCountries: [TopNRow] = []
    var topASNs: [TopNRow] = []
    var eventsByType: [EventCountRow] = []
    var eventsByAction: [EventCountRow] = []
    var idsSignatures: [EventCountRow] = []
    var gaps: [CollectionGap] = []
    var elapsed: Duration = .zero
}

@MainActor
@Observable
final class OverviewLoader {
    var data: OverviewData?
    var error: String?
    var loading = false
    private var task: Task<Void, Never>?

    func load(analytics: AnalyticsService, root: URL, preset: RangePreset, origin: Origin) {
        task?.cancel()
        analytics.ensureOpen(root: root)
        guard analytics.engine != nil else { error = analytics.openError; return }
        loading = true
        task = Task {
            let t0 = ContinuousClock.now
            let f: RecordFilter = { var x = RecordFilter(range: preset.range()); x.origin = origin; return x }()
            let fOut: RecordFilter = { var x = f; x.directions = [.outbound]; return x }()
            let fEvents = f
            let fIDS: RecordFilter = { var x = f; x.eventTypes = [.ids]; return x }()
            do {
                var d = OverviewData(range: f.range)
                async let series = analytics.run { try await $0.timeSeries(f, bucket: preset.bucket) }
                async let totals = analytics.run { try await $0.totals(f.range, origin: origin) }
                async let clients = analytics.run { try await $0.topN(TopNQuery(filter: fOut, dimension: .srcIP, limit: 10)) }
                async let dests = analytics.run { try await $0.topN(TopNQuery(filter: fOut, dimension: .dstIP, limit: 10)) }
                async let ports = analytics.run { try await $0.topN(TopNQuery(filter: f, dimension: .dstPort, limit: 10)) }
                async let countries = analytics.run { try await $0.topN(TopNQuery(filter: fOut, dimension: .dstCountry, limit: 10)) }
                async let asns = analytics.run { try await $0.topN(TopNQuery(filter: fOut, dimension: .dstOrg, limit: 10)) }
                async let byType = analytics.run { try await $0.eventCounts(fEvents, by: "event_type") }
                async let byAction = analytics.run { try await $0.eventCounts(fEvents, by: "action") }
                async let gaps = analytics.run { try await $0.gaps(f.range) }
                async let ids = analytics.run { try await $0.eventCounts(fIDS, by: "ids_signature") }
                d.series = try await series ?? []; d.totals = try await totals
                d.topClients = try await clients ?? []; d.topDestinations = try await dests ?? []; d.topPorts = try await ports ?? []
                d.topCountries = try await countries ?? []; d.topASNs = try await asns ?? []
                d.eventsByType = try await byType ?? []; d.eventsByAction = try await byAction ?? []; d.idsSignatures = try await ids ?? []
                d.gaps = try await gaps ?? []
                d.elapsed = ContinuousClock.now - t0
                if !Task.isCancelled { data = d; error = nil }
            } catch is CancellationError {
            } catch { self.error = error.localizedDescription }
            loading = false
        }
    }
}

struct TrafficChart: View {
    let series: [TimeBucket]
    let gaps: [CollectionGap]
    let range: TimeRange
    var body: some View {
        Chart {
            ForEach(series) { b in
                AreaMark(x: .value("Time", b.bucket.date), y: .value("Outbound", b.outboundBytes), series: .value("Dir", "Outbound")).foregroundStyle(.blue.opacity(0.35))
                AreaMark(x: .value("Time", b.bucket.date), y: .value("Inbound", b.inboundBytes), series: .value("Dir", "Inbound")).foregroundStyle(.green.opacity(0.35))
                LineMark(x: .value("Time", b.bucket.date), y: .value("Bytes", b.bytes)).foregroundStyle(.primary).lineStyle(StrokeStyle(lineWidth: 1))
            }
            ForEach(gaps) { g in
                RectangleMark(xStart: .value("Gap start", max(g.start.date, range.start.date)), xEnd: .value("Gap end", (g.end ?? .now).date))
                    .foregroundStyle(.orange.opacity(0.25))
            }
        }
        .chartXScale(domain: range.start.date...range.end.date)
        .chartYAxis { AxisMarks { v in AxisGridLine(); AxisValueLabel { if let b = v.as(Int64.self) { Text(Format.bytes(b)) } } } }
        .chartLegend(.hidden)
        .frame(height: 180)
        .accessibilityLabel("Traffic over time, bytes per bucket, with collection gaps highlighted")
    }
}

struct TopList: View {
    let title: String
    let rows: [TopNRow]
    var keyLabel: (String) -> String = { $0 }
    var onSelect: ((String) -> Void)? = nil
    var body: some View {
        GroupBox(title) {
            if rows.isEmpty {
                Text("No data in range").font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                let max = Double(rows.map(\.bytes).max() ?? 1)
                VStack(spacing: 4) {
                    ForEach(rows) { r in
                        HStack(spacing: 8) {
                            Text(keyLabel(r.key)).font(.callout.monospaced()).lineLimit(1).frame(width: 150, alignment: .leading)
                            GeometryReader { g in
                                RoundedRectangle(cornerRadius: 3).fill(Color.accentColor.opacity(0.35)).frame(width: g.size.width * CGFloat(Double(r.bytes) / max))
                            }.frame(height: 12)
                            Text(Format.bytes(r.bytes)).font(.caption.monospacedDigit()).frame(width: 70, alignment: .trailing)
                            Text("\(r.flows) flows").font(.caption2).foregroundStyle(.secondary).frame(width: 70, alignment: .trailing)
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { onSelect?(r.key) }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("\(keyLabel(r.key)), \(Format.bytes(r.bytes)), \(r.flows) flows")
                    }
                }
            }
        }
    }
}
