# Performance targets (provisional — to be calibrated against real UCG Fiber output)

Assumptions for a prosumer/small-business UniFi network behind a UCG Fiber (10G WAN capable):
50–300 clients; UniFi's IPFIX export is **sampled** (rate configurable in Traffic Logging), so
flow-record rates are far lower than packet rates. Until a real capture is measured we plan for:

| Signal | Typical sustained | Burst (60 s) | Design ceiling |
|---|---|---|---|
| IPFIX flow records | 200–1,000 /s | 5,000 /s | 20,000 /s |
| IPFIX datagrams | 20–100 /s | 500 /s | 2,000 /s |
| Syslog events | 10–200 /s | 2,000 /s | 10,000 /s |
| Compressed flow bytes on disk | ≈ 45–70 B/flow (zstd, dictionary) | | measured |
| Compressed event bytes on disk | ≈ 120–250 B/event with raw, ≈ 80 B without | | measured |

Derived: 500 flows/s ≈ 43 M flows/day ≈ 2.2–3.0 GB/day → 100 GB (55 % flows) ≈ 18–25 days of
detailed flows; 500 GB ≈ 90–125 days before compaction; day-tier aggregation extends that 5–10×.

## Measurable targets (benchmarks in `Tests/PerformanceTests`, run on M-series, release build)

| ID | Benchmark | Target |
|---|---|---|
| P1 | Sustained ingest 5,000 flows/s + 1,000 events/s for 10 min | 0 receive-queue drops; collector CPU ≤ 1.5 cores; RSS ≤ 400 MB |
| P2 | Burst 20,000 flows/s for 30 s from a 500/s baseline | ≤ 1 % drops, drops reported exactly, recovery to steady state ≤ 10 s |
| P3 | Bounded queues under a stalled persist stage | memory growth capped at configured limits; gap marker written; no crash |
| P4 | 5 concurrent historical queries (24 h range, 50 M rows) during P1 ingest | ingestion unaffected (P1 still met); each query < 3 s; UI main-thread stalls < 16 ms (measured with `os_signpost` + hang detector) |
| P5 | Hour compaction of 60 minute-segments (≈ 3 M rows) during P1 ingest | completes < 60 s; ingest unaffected |
| P6 | Cold start with a 500 GB synthetic store (≈ 12,000 segments in manifest) | collector ready < 5 s; dashboard first paint < 2 s; overview populated < 4 s |
| P7 | Overview aggregates over 30 days from rollups | < 500 ms |
| P8 | "Which internal device talked to IP X" over 90 days | < 5 s with segment pruning by `segment_stats`; < 20 s worst case full scan of 500 GB on NVMe |
| P9 | Memory during 24 h soak at 1,000 flows/s | collector RSS stable (± 10 %) after warm-up |
| P10 | SIGKILL during segment write, ×100 iterations | 0 corrupt manifests; at most the in-flight minute lost, recorded as a gap |
| P11 | Reach budget (10 GB test budget) | retention keeps usage within 97–100 %; rollups/alerts intact |
| P12 | Free space drops below threshold (simulated by a filler file) | ingestion pauses within 1 flush interval, notification fires, resumes after space returns |
| P13 | Live view at 20,000 flows/s | UI receives ≤ 4 batches/s of ≤ 500 records; frame time < 16 ms |
| P14 | Flows table scrolling over 10 M rows (virtualized, page size 500) | page fetch < 150 ms |

Targets marked "measured" are recorded, not asserted, in the first runs; the assertions are then
frozen with a 20 % margin.

## Query plan strategy

* **Segment pruning**: every query starts from the SQLite manifest (`start_ts/end_ts`,
  `segment_stats` min/max for `src_v4/dst_v4`, ports, client ids) to compute the file list; DuckDB
  only sees the files that can match.
* **Rollups first**: any aggregation whose dimensions are covered by `rollup_*` tables is served
  from SQLite; detailed segments are read only for filters the rollups do not cover.
* **Parquet-level pruning**: row-group statistics on `start_time`, `src_v4`, `dst_v4`,
  `dst_port`, `dst_client_id`; segments are sorted by `start_time, src_ip` at compaction.
* **Pagination**: keyset pagination on `(start_time, flow_id)`; never `OFFSET` beyond page 50.
* **Cancellation**: each query runs on a dedicated DuckDB connection; `Task` cancellation calls
  `connection.interrupt()`; the UI shows partial-result states instead of spinners where possible.
* **Concurrency**: dashboard DuckDB `threads = max(2, cores/2)`; collector `threads = 2`.
