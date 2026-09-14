import Foundation
import NetSentryAnalytics
import NetSentryCore
import NetSentryPersistence
import Observation
import os

/// Owns the dashboard's read-only analytical engine over the storage root. Reopened when the root changes.
/// Queries run as cancellable Tasks; the UI keeps the previous result until a new one arrives.
@MainActor
@Observable
final class AnalyticsService {
    private let log = Log.logger("analytics", process: "app")
    private(set) var engine: ReadEngine?
    private(set) var root: URL?
    var openError: String?

    func ensureOpen(root: URL) {
        if self.root == root, engine != nil { return }
        do {
            engine = try ReadEngine(root: root)
            self.root = root
            openError = nil
        } catch {
            engine = nil
            openError = error.localizedDescription
            log.error("cannot open store at \(root.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Runs a query, mapping "store not open yet" to nil instead of an error.
    func run<T: Sendable>(_ body: @escaping @Sendable (ReadEngine) async throws -> T) async throws -> T? {
        guard let engine else { return nil }
        return try await body(engine)
    }
}

/// Time range presets used across views.
enum RangePreset: String, CaseIterable, Identifiable {
    case m15 = "15 min", h1 = "1 hour", h6 = "6 hours", h24 = "24 hours", d7 = "7 days", d30 = "30 days"
    var id: String { rawValue }
    var duration: Duration {
        switch self { case .m15: .seconds(900); case .h1: .seconds(3_600); case .h6: .seconds(21_600); case .h24: .seconds(86_400); case .d7: .seconds(604_800); case .d30: .seconds(2_592_000) }
    }
    var bucket: Duration {
        switch self { case .m15, .h1: .seconds(60); case .h6: .seconds(300); case .h24: .seconds(900); case .d7: .seconds(3_600); case .d30: .seconds(14_400) }
    }
    func range(now: Timestamp = .now) -> TimeRange { .last(duration, now: now) }
}
