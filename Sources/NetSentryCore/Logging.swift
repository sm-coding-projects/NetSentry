import os

/// Unified Logging factory. Telemetry values must always be logged with `privacy: .private`.
public enum Log {
    public static func logger(_ category: String, process: String = "shared") -> Logger {
        Logger(subsystem: "\(Branding.logSubsystemPrefix).\(process)", category: category)
    }
}
