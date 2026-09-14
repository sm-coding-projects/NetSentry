import Foundation

/// Ordered, idempotent schema migrations for meta.sqlite. Never edit a shipped migration; add a new one.
public struct Migration: Sendable {
    public let version: Int
    public let name: String
    public let sql: String
}

public enum MetaSchema {
    public static let migrations: [Migration] = [
        Migration(version: 1, name: "initial", sql: """
        CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);

        CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, json TEXT NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS config_history (id INTEGER PRIMARY KEY, key TEXT NOT NULL, json TEXT NOT NULL, changed_at INTEGER NOT NULL);

        CREATE TABLE IF NOT EXISTS exporters (
          id INTEGER PRIMARY KEY, address TEXT NOT NULL, observation_domain INTEGER NOT NULL,
          kind TEXT NOT NULL CHECK (kind IN ('ipfix','syslog')), name TEXT,
          first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, last_seq INTEGER, restarts INTEGER NOT NULL DEFAULT 0,
          UNIQUE(address, observation_domain, kind));

        CREATE TABLE IF NOT EXISTS ipfix_templates (
          exporter_id INTEGER NOT NULL REFERENCES exporters(id) ON DELETE CASCADE, template_id INTEGER NOT NULL,
          kind TEXT NOT NULL CHECK (kind IN ('data','options')), fields_json TEXT NOT NULL,
          received_at INTEGER NOT NULL, last_refreshed INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          PRIMARY KEY (exporter_id, template_id)) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS clients (
          id INTEGER PRIMARY KEY, display_name TEXT, hostname TEXT, primary_mac TEXT, vlan_id INTEGER, network_id TEXT,
          first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, notes TEXT, trusted INTEGER NOT NULL DEFAULT 0,
          merged_into INTEGER REFERENCES clients(id), created_by TEXT NOT NULL DEFAULT 'auto');
        CREATE INDEX IF NOT EXISTS idx_clients_mac ON clients(primary_mac);

        CREATE TABLE IF NOT EXISTS client_addresses (
          id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE, ip TEXT NOT NULL,
          valid_from INTEGER NOT NULL, valid_to INTEGER, source TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 1.0);
        CREATE INDEX IF NOT EXISTS idx_client_addresses_ip ON client_addresses(ip, valid_from);
        CREATE INDEX IF NOT EXISTS idx_client_addresses_client ON client_addresses(client_id);

        CREATE TABLE IF NOT EXISTS client_macs (
          client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE, mac TEXT NOT NULL,
          valid_from INTEGER NOT NULL, valid_to INTEGER, source TEXT NOT NULL, PRIMARY KEY (client_id, mac, valid_from)) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS tags (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, color TEXT);
        CREATE TABLE IF NOT EXISTS client_tags (client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
          tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE, PRIMARY KEY (client_id, tag_id)) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS expectations (
          id INTEGER PRIMARY KEY, scope_type TEXT NOT NULL, scope_value TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
          note TEXT, created_at INTEGER NOT NULL, UNIQUE(scope_type, scope_value, kind, value));

        CREATE TABLE IF NOT EXISTS first_seen (
          scope_type TEXT NOT NULL, scope_value TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
          first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1,
          PRIMARY KEY (scope_type, scope_value, kind, key)) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS baselines (client_id INTEGER NOT NULL, metric TEXT NOT NULL, bucket_kind TEXT NOT NULL,
          stats_json TEXT NOT NULL, computed_at INTEGER NOT NULL, PRIMARY KEY (client_id, metric, bucket_kind)) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS rules (name TEXT PRIMARY KEY, version INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          params_json TEXT NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS rule_state (rule_name TEXT NOT NULL, key TEXT NOT NULL, json TEXT NOT NULL, updated_at INTEGER NOT NULL,
          PRIMARY KEY (rule_name, key)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS suppressions (id INTEGER PRIMARY KEY, rule_name TEXT NOT NULL, scope_json TEXT NOT NULL,
          expires_at INTEGER, reason TEXT, created_at INTEGER NOT NULL);

        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY, rule_name TEXT NOT NULL, rule_version INTEGER NOT NULL,
          severity INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('open','acknowledged','suppressed','resolved')),
          title TEXT NOT NULL, summary TEXT NOT NULL, explanation_md TEXT NOT NULL,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, first_occurrence INTEGER NOT NULL, last_occurrence INTEGER NOT NULL,
          occurrence_count INTEGER NOT NULL DEFAULT 1, dedupe_key TEXT NOT NULL, client_id INTEGER REFERENCES clients(id),
          entity_json TEXT NOT NULL, evidence_json TEXT NOT NULL, baseline_json TEXT, refs_json TEXT NOT NULL, steps_json TEXT NOT NULL,
          resolved_at INTEGER, origin INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state, created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(dedupe_key);
        CREATE TABLE IF NOT EXISTS alert_notes (id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL, text TEXT NOT NULL);

        CREATE TABLE IF NOT EXISTS annotations (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ts_end INTEGER, kind TEXT NOT NULL,
          title TEXT NOT NULL, text TEXT, refs_json TEXT, created_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_annotations_ts ON annotations(ts);
        CREATE TABLE IF NOT EXISTS bookmarks (id INTEGER PRIMARY KEY, name TEXT NOT NULL, query_json TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS saved_searches (id INTEGER PRIMARY KEY, name TEXT NOT NULL, view TEXT NOT NULL, query_json TEXT NOT NULL,
          columns_json TEXT, sort_json TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);

        CREATE TABLE IF NOT EXISTS segments (
          id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('flows','events')),
          tier TEXT NOT NULL CHECK (tier IN ('minute','hour','day')),
          start_ts INTEGER NOT NULL, end_ts INTEGER NOT NULL, path TEXT NOT NULL UNIQUE, row_count INTEGER NOT NULL,
          bytes INTEGER NOT NULL, raw_bytes INTEGER NOT NULL DEFAULT 0, compacted INTEGER NOT NULL DEFAULT 0,
          state TEXT NOT NULL CHECK (state IN ('writing','finalized','compacting','missing','corrupt','deleted')),
          schema_version INTEGER NOT NULL, enrichment_version INTEGER NOT NULL, parser_versions_json TEXT,
          sha256 TEXT, created_at INTEGER NOT NULL, finalized_at INTEGER, origin INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_segments_range ON segments(kind, start_ts, end_ts);
        CREATE TABLE IF NOT EXISTS segment_stats (segment_id INTEGER NOT NULL REFERENCES segments(id) ON DELETE CASCADE,
          column TEXT NOT NULL, min_value INTEGER, max_value INTEGER, distinct_estimate INTEGER, PRIMARY KEY (segment_id, column)) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS gaps (id INTEGER PRIMARY KEY, start_ts INTEGER NOT NULL, end_ts INTEGER, kind TEXT NOT NULL,
          reason TEXT NOT NULL, details_json TEXT);
        CREATE INDEX IF NOT EXISTS idx_gaps_start ON gaps(start_ts);

        CREATE TABLE IF NOT EXISTS rollup_minute (
          bucket INTEGER NOT NULL, origin INTEGER NOT NULL, client_id INTEGER NOT NULL DEFAULT 0, direction INTEGER NOT NULL,
          flows INTEGER NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL, denied INTEGER NOT NULL DEFAULT 0,
          allowed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket, origin, client_id, direction)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS rollup_hour (
          bucket INTEGER NOT NULL, origin INTEGER NOT NULL, client_id INTEGER NOT NULL DEFAULT 0, dst_ip TEXT NOT NULL DEFAULT '',
          dst_port INTEGER NOT NULL DEFAULT 0, protocol INTEGER NOT NULL DEFAULT 0, direction INTEGER NOT NULL,
          dst_country TEXT, dst_asn INTEGER, flows INTEGER NOT NULL, bytes INTEGER NOT NULL, packets INTEGER NOT NULL,
          denied INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket, origin, client_id, dst_ip, dst_port, protocol, direction)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS rollup_day (
          bucket INTEGER NOT NULL, origin INTEGER NOT NULL, client_id INTEGER NOT NULL DEFAULT 0, dst_country TEXT NOT NULL DEFAULT '',
          dst_asn INTEGER NOT NULL DEFAULT 0, dst_port INTEGER NOT NULL DEFAULT 0, protocol INTEGER NOT NULL DEFAULT 0,
          flows INTEGER NOT NULL, bytes INTEGER NOT NULL, denied INTEGER NOT NULL DEFAULT 0, first_seen_new INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (bucket, origin, client_id, dst_country, dst_asn, dst_port, protocol)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS daily_summary (day INTEGER NOT NULL, origin INTEGER NOT NULL, json TEXT NOT NULL, PRIMARY KEY (day, origin)) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS parser_registry (name TEXT PRIMARY KEY, version INTEGER NOT NULL, family TEXT NOT NULL, description TEXT, verified INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS enrichment_versions (version INTEGER PRIMARY KEY, geoip_build TEXT, changed_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL, started_at INTEGER NOT NULL,
          finished_at INTEGER, progress REAL NOT NULL DEFAULT 0, message TEXT);
        CREATE TABLE IF NOT EXISTS trusted_resolvers (ip TEXT PRIMARY KEY, note TEXT);
        CREATE TABLE IF NOT EXISTS internal_networks (cidr TEXT PRIMARY KEY, name TEXT, vlan_id INTEGER);
        """),
        Migration(version: 2, name: "alerts-without-client-fk", sql: """
        CREATE TABLE alerts_v2 (
          id INTEGER PRIMARY KEY, rule_name TEXT NOT NULL, rule_version INTEGER NOT NULL,
          severity INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('open','acknowledged','suppressed','resolved')),
          title TEXT NOT NULL, summary TEXT NOT NULL, explanation_md TEXT NOT NULL,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, first_occurrence INTEGER NOT NULL, last_occurrence INTEGER NOT NULL,
          occurrence_count INTEGER NOT NULL DEFAULT 1, dedupe_key TEXT NOT NULL, client_id INTEGER,
          entity_json TEXT NOT NULL, evidence_json TEXT NOT NULL, baseline_json TEXT, refs_json TEXT NOT NULL, steps_json TEXT NOT NULL,
          resolved_at INTEGER, origin INTEGER NOT NULL DEFAULT 0);
        INSERT INTO alerts_v2 SELECT id, rule_name, rule_version, severity, state, title, summary, explanation_md, created_at, updated_at, first_occurrence,
          last_occurrence, occurrence_count, dedupe_key, client_id, entity_json, evidence_json, baseline_json, refs_json, steps_json, resolved_at, origin FROM alerts;
        DROP TABLE alerts;
        ALTER TABLE alerts_v2 RENAME TO alerts;
        CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state, created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(dedupe_key);
        CREATE INDEX IF NOT EXISTS idx_alerts_client ON alerts(client_id);
        """),
    ]

    public static let currentVersion = migrations.map(\.version).max() ?? 0
}

public enum Migrator {
    /// Applies pending migrations inside one transaction each. Refuses databases newer than this binary.
    public static func migrate(_ db: SQLiteDatabase) throws {
        try db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)")
        let applied = try db.scalar("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").int64 ?? 0
        if applied > Int64(MetaSchema.currentVersion) {
            throw SQLiteError.migration("Database schema version \(applied) is newer than this version of the app supports (\(MetaSchema.currentVersion)).")
        }
        for m in MetaSchema.migrations where Int64(m.version) > applied {
            // Table rebuilds must not cascade through foreign keys; the pragma is a no-op inside a transaction, so set it outside.
            try db.execute("PRAGMA foreign_keys = OFF")
            defer { try? db.execute("PRAGMA foreign_keys = ON") }
            try db.transaction {
                try db.execute(m.sql)
                try db.run("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                           [m.version, m.name, NetSentryCore.Timestamp.now.microseconds])
            }
        }
    }

    public static func appliedVersions(_ db: SQLiteDatabase) throws -> [Int] {
        try db.query("SELECT version FROM schema_migrations ORDER BY version").compactMap { $0.int("version") }
    }
}
import NetSentryCore
