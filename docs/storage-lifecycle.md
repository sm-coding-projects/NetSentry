# Storage and retention lifecycle

## Budget model

* `budgetBytes` ∈ [5 GB, 500 GB] (presets 5/10/25/50/100/250/500 + custom). It is a ceiling on
  **physical bytes** under the storage root (segments + SQLite files + WAL + tmp + exports are all
  counted; exports count against the operational reserve).
* Allocation (defaults, adjustable): flows 55 %, events 20 %, raw 10 %, meta/rollups/alerts 10 %,
  reserve 5 %. Allocations are *soft* targets used to decide which category to trim first when
  the total exceeds the budget; a category may temporarily exceed its share if others are below.
* Safety threshold: free space on the volume must stay ≥ `max(10 GB, 5 % of volume size)`
  (mode `auto`) or a user-fixed value. Checked before every segment flush.

## Write path

1. Records accumulate in the collector's DuckDB in-memory staging table (bounded by
   `hotBuffer.maxRecords`; the ring buffer for the live view is separate and smaller).
2. Every 60 s (or 50k records, or on graceful shutdown) a **minute segment** is written:
   `COPY staging TO tmp/x.parquet.tmp (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 65536)`,
   `fsync`, `rename`, then one SQLite transaction inserts the manifest row, updates
   `rollup_minute`/`first_seen`/`exporters`/`gaps`, and records `segment_stats`.
3. If the flush fails (disk full, I/O error): the staging batch is retained up to a memory cap
   (default 256 MB), reception pauses with a `storage_pause` gap marker, health goes red, and a
   notification fires. When space returns, the batch is flushed and the gap closed.

## Compaction (background, low QoS, cancellable)

| Trigger | Action |
|---|---|
| Hour boundary + 5 min, ≥ 2 minute-segments for that hour | Merge minute segments → one hour segment (sorted by `start_time`, then `src_ip`). Verify row counts match, then delete minute files in one manifest transaction. |
| Day boundary + 1 h | Merge hour segments → day segment; `rollup_hour`/`rollup_day` finalized for that day; `daily_summary` written. |
| Retention stage 2 | Rewrite event segments older than the raw-retention window with `raw` and `raw_bytes` set to NULL. |
| Retention stage 3 ("compact older detailed records") | Rewrite flow segments older than the compaction window into a **compacted form**: same schema, but flows aggregated per (5-minute bucket, src, dst, dst_port, protocol, direction, action) with summed counters and `flow_count`. Original rows are gone; the segment gets `tier = 'day'`, `compacted = 1`. UI labels these "aggregated". |

Compaction never rewrites a segment in place: new file → verify → manifest swap → delete old.
Queries during compaction see either the old or the new set, never both (manifest snapshot).

## Retention stages (run when physical usage > budget, or free space < threshold, or hourly)

1. Drop optional raw IPFIX datagram captures (`captures/`, only exist when the user enabled
   packet capture for diagnostics).
2. Null out `raw` in event segments older than `rawRetentionDays` (default 7) where
   `parse_status != unparsed` (unparsed events keep raw — it is their only content).
3. Compact flow segments older than `compactAfterDays` (default 30) into the aggregated form.
4. Rollups (minute ≤ 90 days, hour ≤ 2 years, day forever) are never deleted by budget pressure;
   minute rollups are trimmed only by their own age policy.
5. Delete oldest detailed segments (flows and events alternately, weighted by allocation
   overshoot) until usage ≤ 97 % of budget and free space ≥ threshold + 1 GB hysteresis.
6. Alerts, annotations, bookmarks, saved searches, `daily_summary`, and `gaps` are never deleted
   automatically. Alert `refs_json` may point at deleted segments; the UI shows "supporting
   records expired" with the evidence snapshot that was embedded in the alert.
7. If after stage 5 the safety threshold is still violated (another app filled the disk), the
   collector pauses ingestion (gap marker `disk_pressure`) and notifies. It resumes automatically
   when the threshold is satisfied for 60 s.

## Changing the budget

`retention.preview` computes, without deleting: usage after change, which segments would go
(count, time span, oldest surviving record per category), and the estimated retention at the
current ingestion rate. Shrinking requires the user to confirm the preview. Growing takes effect
immediately.

## Retention estimate

`estimatedDays = (budget × allocation.flows) / (avg flow bytes/day over trailing 7 days)`, shown
alongside the events figure and the worst-case of the two. Average compressed record sizes are
measured from finalized segments, not assumed.

## Implementation notes (Phase 3)

* Segment writer: `NetSentryPersistence/Segments/SegmentWriter.swift`; manager: `StorageManager.swift`.
* Manifest row counts come from the staging table (`SELECT COUNT(*)`), never from in-memory counters.
* Startup verification retries a read once before marking a segment corrupt; `verify()` re-checks
  missing/corrupt segments and restores them when they pass.
* Stage 4 (rollup age trimming) and the daily summary writer are not implemented yet.

## Startup recovery

1. Open `meta.sqlite`; run `PRAGMA quick_check`; if it fails, restore from the last daily backup
   (`meta.backup.sqlite`, produced by the SQLite online backup API) and report.
2. Apply migrations inside a transaction; refuse to run if the on-disk `schema_version` is newer
   than the binary supports.
3. Remove `tmp/*.parquet.tmp`; reconcile manifest ↔ filesystem (see schemas doc).
4. Verify the newest 3 segments per kind (Parquet footer readable, row count matches manifest);
   mark corrupt segments and quarantine them.
5. Recompute usage by category from the manifest and `stat`.
6. Insert a `gaps` row for [last_finalized_end, now) with reason `collector_down` (closed as soon as
   the first record arrives).

## Backup and restore

Settings › Storage › "Back up settings and findings…" exports a `.netsentry-backup` zip containing
`meta.sqlite` tables config, clients, client_addresses, tags, expectations, trusted_resolvers,
internal_networks, rules, suppressions, alerts, alert_notes, annotations, bookmarks, saved_searches,
daily_summary. Telemetry segments are not included. Restore merges by natural keys.
