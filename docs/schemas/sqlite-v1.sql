-- NetSentry meta.sqlite schema v1 (excerpt; authoritative DDL lives in Packages/NetSentryPersistence/Migrations)
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);

CREATE TABLE config (key TEXT PRIMARY KEY, json TEXT NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE exporters (
  id INTEGER PRIMARY KEY, address TEXT NOT NULL, observation_domain INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('ipfix','syslog')), name TEXT,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, last_seq INTEGER, restarts INTEGER NOT NULL DEFAULT 0,
  UNIQUE(address, observation_domain, kind));

CREATE TABLE clients (
  id INTEGER PRIMARY KEY, display_name TEXT, hostname TEXT, primary_mac TEXT, vlan_id INTEGER, network_id TEXT,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, notes TEXT, trusted INTEGER NOT NULL DEFAULT 0,
  merged_into INTEGER REFERENCES clients(id), created_by TEXT NOT NULL DEFAULT 'auto');

CREATE TABLE client_addresses (
  client_id INTEGER NOT NULL REFERENCES clients(id), ip TEXT NOT NULL,
  valid_from INTEGER NOT NULL, valid_to INTEGER, source TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 1.0);
CREATE INDEX idx_client_addresses_ip ON client_addresses(ip, valid_from);

CREATE TABLE first_seen (
  scope_type TEXT NOT NULL, scope_value TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (scope_type, scope_value, kind, key)) WITHOUT ROWID;

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY, rule_name TEXT NOT NULL, rule_version INTEGER NOT NULL,
  severity INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('open','acknowledged','suppressed','resolved')),
  title TEXT NOT NULL, summary TEXT NOT NULL, explanation_md TEXT NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, first_occurrence INTEGER NOT NULL, last_occurrence INTEGER NOT NULL,
  occurrence_count INTEGER NOT NULL DEFAULT 1, dedupe_key TEXT NOT NULL, client_id INTEGER REFERENCES clients(id),
  entity_json TEXT NOT NULL, evidence_json TEXT NOT NULL, baseline_json TEXT, refs_json TEXT NOT NULL, steps_json TEXT NOT NULL,
  resolved_at INTEGER, origin INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX idx_alerts_dedupe ON alerts(dedupe_key, state) WHERE state IN ('open','acknowledged');

CREATE TABLE segments (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('flows','events')), tier TEXT NOT NULL CHECK (tier IN ('minute','hour','day')),
  start_ts INTEGER NOT NULL, end_ts INTEGER NOT NULL, path TEXT NOT NULL UNIQUE, row_count INTEGER NOT NULL,
  bytes INTEGER NOT NULL, raw_bytes INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('writing','finalized','compacting','missing','corrupt','deleted')),
  schema_version INTEGER NOT NULL, enrichment_version INTEGER NOT NULL, parser_versions_json TEXT,
  sha256 TEXT, created_at INTEGER NOT NULL, finalized_at INTEGER, origin INTEGER NOT NULL DEFAULT 0);
CREATE INDEX idx_segments_range ON segments(kind, start_ts, end_ts) WHERE state = 'finalized';

CREATE TABLE gaps (id INTEGER PRIMARY KEY, start_ts INTEGER NOT NULL, end_ts INTEGER, kind TEXT NOT NULL, reason TEXT NOT NULL, details_json TEXT);

CREATE TABLE rollup_minute (
  bucket INTEGER NOT NULL, origin INTEGER NOT NULL, client_id INTEGER, direction INTEGER NOT NULL,
  flows INTEGER NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL, denied INTEGER NOT NULL DEFAULT 0, allowed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, origin, client_id, direction)) WITHOUT ROWID;
