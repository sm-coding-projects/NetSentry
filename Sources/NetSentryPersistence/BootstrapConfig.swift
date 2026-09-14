import Foundation
import NetSentryCore

/// JSON mirror of the configuration so the collector can locate the storage root before opening SQLite,
/// and so the dashboard can show settings when the collector is not running.
public enum BootstrapConfig {
    public static func load(from url: URL = StorageLocations.bootstrapConfigURL()) -> CollectorConfiguration? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(CollectorConfiguration.self, from: data)
    }

    public static func save(_ config: CollectorConfiguration, to url: URL = StorageLocations.bootstrapConfigURL()) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try enc.encode(config)
        let tmp = url.appendingPathExtension("tmp")
        try data.write(to: tmp, options: .atomic)
        _ = try fm.replaceItemAt(url, withItemAt: tmp)
        chmod(url.path, 0o600)
    }

    /// Loads the bootstrap file or creates a default one.
    public static func loadOrCreate() -> CollectorConfiguration {
        if let c = load() { return c }
        let c = StorageLocations.defaultConfiguration()
        try? save(c)
        return c
    }
}
