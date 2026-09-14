import Foundation
import NetSentryCore

/// Owner of `meta.sqlite`. All access is serialized through this actor.
public actor MetaStore {
    public let root: URL
    public nonisolated let db: SQLiteDatabase
    private let log = Log.logger("metastore")

    public static func metaPath(root: URL) -> String { root.appending(path: "meta.sqlite").path }

    /// Opens (creating and migrating if needed) the metadata database under `root`.
    public init(root: URL, readOnly: Bool = false) throws {
        self.root = root
        let fm = FileManager.default
        if !readOnly {
            try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for sub in ["flows", "events", "tmp", "geoip", "exports", "backups"] {
                try fm.createDirectory(at: root.appending(path: sub), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            }
        }
        db = try SQLiteDatabase(path: Self.metaPath(root: root), readOnly: readOnly)
        if !readOnly {
            try db.quickCheck()
            try Migrator.migrate(db)
        }
    }

    // MARK: Config

    public func loadConfiguration() throws -> CollectorConfiguration? {
        guard let json = try db.scalar("SELECT json FROM config WHERE key = 'collector'").string,
              let data = json.data(using: .utf8) else { return nil }
        return try JSONDecoder().decode(CollectorConfiguration.self, from: data)
    }

    public func saveConfiguration(_ config: CollectorConfiguration) throws {
        let data = try JSONEncoder().encode(config)
        let json = String(decoding: data, as: UTF8.self)
        let now = Timestamp.now
        try db.transaction {
            try db.run("INSERT INTO config (key, json, updated_at) VALUES ('collector', ?, ?) ON CONFLICT(key) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at", [json, now])
            try db.run("INSERT INTO config_history (key, json, changed_at) VALUES ('collector', ?, ?)", [json, now])
            try db.run("DELETE FROM config_history WHERE key = 'collector' AND id NOT IN (SELECT id FROM config_history WHERE key = 'collector' ORDER BY id DESC LIMIT 50)")
        }
    }

    // MARK: Gaps

    @discardableResult
    public func openGap(kind: GapKind, reason: String, at: Timestamp = .now, details: [String: String] = [:]) throws -> Int64 {
        let json = String(decoding: try JSONEncoder().encode(details), as: UTF8.self)
        try db.run("INSERT INTO gaps (start_ts, end_ts, kind, reason, details_json) VALUES (?, NULL, ?, ?, ?)", [at, kind.rawValue, reason, json])
        return db.lastInsertRowID
    }

    public func closeGap(id: Int64, at: Timestamp = .now) throws {
        try db.run("UPDATE gaps SET end_ts = ? WHERE id = ? AND end_ts IS NULL", [at, id])
    }

    public func closeAllOpenGaps(at: Timestamp = .now) throws {
        try db.run("UPDATE gaps SET end_ts = ? WHERE end_ts IS NULL", [at])
    }

    public func gaps(from: Timestamp, to: Timestamp, limit: Int = 1000) throws -> [CollectionGap] {
        try db.query("SELECT id, start_ts, end_ts, kind, reason, details_json FROM gaps WHERE start_ts <= ? AND (end_ts IS NULL OR end_ts >= ?) ORDER BY start_ts DESC LIMIT ?",
                     [to, from, limit]).map(Self.gap(from:))
    }

    public func openGaps() throws -> [CollectionGap] {
        try db.query("SELECT id, start_ts, end_ts, kind, reason, details_json FROM gaps WHERE end_ts IS NULL ORDER BY start_ts").map(Self.gap(from:))
    }

    private static func gap(from row: SQLRow) -> CollectionGap {
        let details = row.string("details_json").flatMap { try? JSONDecoder().decode([String: String].self, from: Data($0.utf8)) } ?? [:]
        return CollectionGap(id: row.int64("id") ?? 0, start: row.timestamp("start_ts") ?? .now, end: row.timestamp("end_ts"),
                             kind: GapKind(rawValue: row.string("kind") ?? "") ?? .collectorDown, reason: row.string("reason") ?? "", details: details)
    }

    // MARK: Exporters

    public func upsertExporter(kind: ListenerKind, key: ExporterKey, seenAt: Timestamp, lastSequence: UInt32?, restarted: Bool) throws -> Int32 {
        try db.run("""
            INSERT INTO exporters (address, observation_domain, kind, first_seen, last_seen, last_seq, restarts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(address, observation_domain, kind) DO UPDATE SET last_seen = excluded.last_seen,
              last_seq = COALESCE(excluded.last_seq, exporters.last_seq), restarts = exporters.restarts + excluded.restarts
            """, [key.address, key.observationDomain, kind.rawValue, seenAt, seenAt, lastSequence, restarted ? 1 : 0])
        let id = try db.scalar("SELECT id FROM exporters WHERE address = ? AND observation_domain = ? AND kind = ?",
                               [key.address, key.observationDomain, kind.rawValue]).int64 ?? 0
        return Int32(id)
    }

    // MARK: Maintenance

    public func backupMeta() throws -> URL {
        let dest = root.appending(path: "backups/meta.backup.sqlite")
        try? FileManager.default.removeItem(at: dest)
        try db.backup(to: dest.path)
        return dest
    }

    public func checkpoint() { db.checkpoint() }
    public func quickCheck() throws { try db.quickCheck() }
}
