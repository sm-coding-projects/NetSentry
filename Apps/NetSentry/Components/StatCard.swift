import SwiftUI

struct StatCard: View {
    let title: String
    let value: String
    var detail: String? = nil
    var systemImage: String? = nil
    var tint: Color = .accentColor

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                if let systemImage { Image(systemName: systemImage).foregroundStyle(tint).accessibilityHidden(true) }
                Text(title).font(.caption).foregroundStyle(.secondary)
            }
            Text(value).font(.title2.monospacedDigit().weight(.semibold)).lineLimit(1).minimumScaleFactor(0.6)
            if let detail { Text(detail).font(.caption2).foregroundStyle(.tertiary).lineLimit(2) }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value). \(detail ?? "")")
    }
}

struct StatusBadge: View {
    enum Kind { case ok, warning, error, neutral }
    let text: String
    let kind: Kind
    var body: some View {
        Text(text)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
            .accessibilityElement(children: .combine)
    }
    private var color: Color {
        switch kind { case .ok: .green; case .warning: .orange; case .error: .red; case .neutral: .secondary }
    }
}

enum Format {
    static func bytes(_ b: Int64) -> String { ByteCountFormatter.string(fromByteCount: b, countStyle: .file) }
    static func bytes(_ b: UInt64) -> String { bytes(Int64(clamping: b)) }
    static func count(_ n: UInt64) -> String { n.formatted(.number.grouping(.automatic)) }
    static func rate(_ r: Double, unit: String) -> String { r < 10 ? String(format: "%.1f %@", r, unit) : "\(Int(r.rounded())) \(unit)" }
    static func time(_ t: NetSentryCore.Timestamp?) -> String {
        guard let t else { return "never" }
        return t.date.formatted(date: .abbreviated, time: .standard)
    }
    static func relative(_ t: NetSentryCore.Timestamp?) -> String {
        guard let t else { return "never" }
        return t.date.formatted(.relative(presentation: .named))
    }
}
import NetSentryCore
