import AppKit
import Foundation
import NetSentryCore
import os

/// Observes sleep/wake and system clock changes and turns them into collection-gap markers.
/// AppKit notifications require a running NSApplication run loop (the collector is an LSUIElement app).
@MainActor
final class SystemObservers {
    private let log = Log.logger("system", process: "collector")
    private var tokens: [any NSObjectProtocol] = []
    private let health: HealthMonitor
    private var lastWall = Timestamp.now
    private var lastMono = MonotonicClock.continuousNanoseconds
    private var clockTimer: Timer?

    init(health: HealthMonitor) {
        self.health = health
        let ws = NSWorkspace.shared.notificationCenter
        tokens.append(ws.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [health] _ in
            Task { await health.openGap(.sleep, reason: "Mac is going to sleep") }
        })
        tokens.append(ws.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [health] _ in
            Task { await health.closeGap(.sleep) }
        })
        tokens.append(NotificationCenter.default.addObserver(forName: .NSSystemClockDidChange, object: nil, queue: .main) { [weak self] _ in
            // Delivered on the main queue (queue: .main), so we are already on the main actor.
            MainActor.assumeIsolated { self?.clockChanged(reason: "NSSystemClockDidChange") }
        })
        // Belt and braces: compare wall vs continuous clocks every 30 s to catch jumps without a notification.
        clockTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkClockDrift() }
        }
    }

    private func checkClockDrift() {
        let wall = Timestamp.now
        let mono = MonotonicClock.continuousNanoseconds
        let wallDelta = wall.microseconds - lastWall.microseconds
        let monoDelta = Int64((mono - lastMono) / 1_000)
        lastWall = wall
        lastMono = mono
        if abs(wallDelta - monoDelta) > 5_000_000 {
            clockChanged(reason: "Wall clock moved \((wallDelta - monoDelta) / 1_000_000) s relative to the monotonic clock")
        }
    }

    private func clockChanged(reason: String) {
        log.notice("System clock change detected: \(reason, privacy: .public)")
        Task {
            await health.openGap(.clockChange, reason: reason)
            await health.closeGap(.clockChange)   // instantaneous marker; the gap row records the moment
            await health.setWarning(HealthWarning(id: "clock", level: .info, title: "System clock changed", detail: reason, since: .now))
        }
    }
}
