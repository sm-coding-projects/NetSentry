# Data schemas (v1)

All schemas carry `schema_version`. Parquet segments embed `netsentry.schema_version`,
`netsentry.enrichment_version`, `netsentry.parser_versions` and `netsentry.origin` in the file
key-value metadata. Timestamps are **UTC epoch microseconds** (`Int64`) unless stated. IP
addresses are stored as canonical text (RFC 5952 for IPv6) plus a `*_v4` UInt32 column for
IPv4 range queries; `ip_version` is 4 or 6.

## 1. Flow record — Parquet segment `flows/*.parquet`

| Column | Type | Notes |
|---|---|---|
| flow_id | INT64 | collector-assigned, unique within workspace (segment_seq << 32 \| row) |
| origin | UINT8 | 0 live, 1 simulated, 2 imported |
| exporter_id | INT32 | FK `exporters.id` (SQLite) |
| observation_domain_id | UINT32 | IPFIX header |
| export_seq | UINT32 | IPFIX sequence number of the message |
| received_at | INT64 | collector monotonic-corrected wall clock at socket read |
| export_time | INT64 | IPFIX header export time (seconds → µs) |
| start_time / end_time | INT64 | from IE 150–159 (abs/delta/µs/ns variants), else export_time |
| clock_skew_us | INT64 | exporter export_time − received_at, for the exporter at that moment |
| ip_version | UINT8 | |
| src_ip / dst_ip | VARCHAR | dictionary-encoded |
| src_v4 / dst_v4 | UINT32 (nullable) | |
| src_port / dst_port | UINT16 | |
| protocol | UINT8 | IE 4 |
| tcp_flags | UINT16 | IE 6 (8- or 16-bit) |
| icmp_type / icmp_code | UINT8 nullable | IE 176/177 or derived from IE 32 |
| packets / octets | UINT64 | delta counts (IE 2/1) |
| rev_packets / rev_octets | UINT64 nullable | biflow reverse (PEN 29305 IE 2/1) |
| ingress_if / egress_if | UINT32 nullable | IE 10/14 |
| src_vlan / dst_vlan | UINT16 nullable | IE 58/59 |
| flow_direction | UINT8 nullable | IE 61 raw value |
| flow_end_reason | UINT8 nullable | IE 136 |
| sampling_interval | UINT32 nullable | from options template (IE 34/305/309) at the time |
| post_nat_src_ip / post_nat_dst_ip | VARCHAR nullable | IE 225/226 (v4), 281/282 (v6) |
| post_nat_src_port / post_nat_dst_port | UINT16 nullable | IE 227/228 |
| app_id | VARCHAR nullable | IE 95 / DPI hints if exporter sends them |
| ie_extra | JSON (VARCHAR) nullable | `{"pen:id": "<base64 or int>"}` for unknown/enterprise IEs |
| **enrichment (as-known-at-ingest)** | | |
| direction | UINT8 | 0 unknown, 1 outbound, 2 inbound, 3 internal, 4 transit |
| src_internal / dst_internal | BOOLEAN | |
| src_client_id / dst_client_id | INT64 nullable | FK `clients.id` |
| dst_country / src_country | VARCHAR(2) nullable | |
| dst_asn / src_asn | UINT32 nullable | |
| dst_org | VARCHAR nullable | ASN organization (dictionary) |
| service | VARCHAR nullable | IANA name for (dst_port, protocol) |
| enrichment_version | UINT16 | |
| schema_version | UINT16 | =1 |

## 2. Syslog event — Parquet segment `events/*.parquet`

| Column | Type | Notes |
|---|---|---|
| event_id | INT64 | |
| origin | UINT8 | |
| received_at | INT64 | |
| event_time | INT64 nullable | parsed from message (3164 has no year/zone → inferred, flagged) |
| time_inferred | BOOLEAN | |
| source_ip | VARCHAR | sender address |
| transport | UINT8 | 0 udp, 1 tcp |
| syslog_version | UINT8 | 0 = RFC 3164 style, 1 = RFC 5424 |
| facility / severity | UINT8 | from PRI; null-safe defaults 1/6 if PRI missing (flagged in attrs) |
| hostname | VARCHAR nullable | |
| app_name / proc_id / msg_id | VARCHAR nullable | |
| structured_data | JSON nullable | RFC 5424 SD-elements |
| message | VARCHAR | MSG part |
| raw | VARCHAR nullable | exact bytes as received (UTF-8 lossy, with `raw_bytes` fallback when not UTF-8); nulled by retention stage 2 |
| raw_bytes | BLOB nullable | only when not valid UTF-8 |
| parser_name / parser_version | VARCHAR / UINT16 | |
| parse_status | UINT8 | 0 parsed, 1 partial, 2 unparsed |
| event_type | UINT8 | 0 unknown, 1 firewall, 2 ids, 3 auth, 4 vpn, 5 dhcp, 6 dns, 7 system, 8 wifi/client, 9 unifi-other |
| src_ip / dst_ip / src_v4 / dst_v4 | | as flows |
| src_port / dst_port / protocol | | |
| action | UINT8 nullable | 0 unknown, 1 allow, 2 deny/drop, 3 reject, 4 block(ids), 5 alert |
| in_iface / out_iface | VARCHAR nullable | |
| vlan | UINT16 nullable | |
| rule_id / rule_name | VARCHAR nullable | |
| username | VARCHAR nullable | |
| device_id | VARCHAR nullable | MAC or UniFi device id |
| ids_signature_id / ids_signature / ids_category / ids_severity | INT64 / VARCHAR / VARCHAR / UINT8 nullable | |
| src_client_id / dst_client_id / direction / dst_country / dst_asn | | as flows |
| attrs | JSON nullable | everything else the parser extracted (netfilter k=v pairs etc.) |
| enrichment_version / schema_version | UINT16 | |

## 3. SQLite: `meta.sqlite` (see `sqlite-v1.sql` for DDL)

* `schema_migrations(version, applied_at)`
* `config(key, json, updated_at)`, `config_history`
* `exporters(id, address, observation_domain, first_seen, last_seen, last_seq, restarts, name, kind)`
* `ipfix_templates(exporter_id, domain, template_id, kind, fields_json, received_at, last_refreshed, expires_at, active)`
* `clients(id, display_name, hostname, primary_mac, vlan_id, network_id, first_seen, last_seen, notes, trusted, merged_into, created_by)`
* `client_addresses(client_id, ip, valid_from, valid_to, source, confidence)` — historical IP↔client
* `client_macs(client_id, mac, valid_from, valid_to, source)`
* `tags(id, name, color)`, `client_tags(client_id, tag_id)`
* `expectations(id, scope_type, scope_value, kind, value, note, created_at)` — expected countries/ASNs/ports/destinations/behaviors per client, VLAN, or global
* `trusted_resolvers(ip, note)`; `internal_networks(cidr, name, vlan_id)`
* `first_seen(scope_type, scope_value, kind, key, first_seen, last_seen, count)` — kinds: destination, country, asn, port_proto, service; scope client or global
* `baselines(client_id, metric, bucket_kind, stats_json, computed_at)`
* `rules(name, version, enabled, params_json, updated_at)`, `rule_state(name, key, json)`
* `suppressions(id, rule_name, scope_json, expires_at, reason)`
* `alerts(id, rule_name, rule_version, severity, state, title, summary, explanation_md, created_at, updated_at, first_occurrence, last_occurrence, occurrence_count, dedupe_key, client_id, entity_json, evidence_json, baseline_json, refs_json, steps_json, resolved_at, resolved_by_note)`
* `alert_notes(alert_id, created_at, text)`
* `annotations(id, ts, ts_end, kind, title, text, refs_json)`; `bookmarks(id, name, query_json, created_at)`
* `saved_searches(id, name, view, query_json, columns_json, sort_json)`
* `segments(id, kind, tier, start_ts, end_ts, path, row_count, bytes, raw_bytes, state, schema_version, enrichment_version, parser_versions_json, sha256, created_at, finalized_at, origin)`
* `segment_stats(segment_id, column, min, max, distinct_estimate)` — used for pruning
* `gaps(id, start_ts, end_ts, kind, reason, details_json)` — collection gaps (sleep, listener down, drops, storage pause, clock change)
* `rollup_minute(bucket, origin, client_id, direction, flows, packets, bytes, denied, allowed)`
* `rollup_hour(bucket, origin, client_id, dst_ip, dst_port, protocol, direction, dst_country, dst_asn, flows, bytes, packets, denied)`
* `rollup_day(bucket, origin, client_id, dst_country, dst_asn, dst_port, protocol, flows, bytes, denied, first_seen_new)`
* `daily_summary(day, json)` — survives detailed deletion
* `parser_registry(name, version, family, description)`; `enrichment_versions(version, geoip_build, changed_at)`
* `jobs(id, kind, state, started_at, finished_at, progress, message)`

## 4. Alert JSON sub-schemas

```
entity_json:  { "kind": "client|ip|asn|country|port|exporter", "id": ..., "label": ... }
evidence_json:{ "metrics": {name: value}, "window": {start,end}, "samples": [{...}] }
baseline_json:{ "kind": "threshold|rolling", "value": ..., "unit": ..., "period": ..., "n": ... }
refs_json:    { "flows": [{"segment": id, "flow_id": ...}], "events": [...], "gaps": [...] }
steps_json:   ["Check whether ...", ...]
```

## 5. Segment naming and directory layout

```
<Store>/
  meta.sqlite (+ -wal/-shm)
  flows/YYYY/MM/DD/flows_m_<startUnix>_<seq>.parquet        # minute tier
  flows/YYYY/MM/DD/flows_h_<startUnix>.parquet              # hour tier
  flows/YYYY/MM/flows_d_<startUnix>.parquet                 # day tier
  events/…                                                  # same tiers
  tmp/                                                      # *.parquet.tmp — removed on startup if not in manifest
  geoip/                                                    # user-supplied .mmdb
  exports/
```
Finalization: write `tmp/<name>.parquet.tmp` → fsync → `rename` into place → insert manifest row
with state `finalized` in the same SQLite transaction that records rollup updates → fsync dir.
Startup recovery: any file not in the manifest is quarantined to `tmp/orphan-…` and reported;
any manifest row without a file is marked `missing` and reported as an integrity issue.
