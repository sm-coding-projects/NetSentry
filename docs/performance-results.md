# Performance results

Measured with `NETSENTRY_BENCH=1 swift test --filter Benchmarks` (see `Tests/NetSentryBenchmarks`) on the
development Mac (Apple silicon, internal SSD). Synthetic UCG-shaped IPFIX from `SyntheticFlowSource` (60 clients,
400 destinations); real gateway data compresses less well than this repetitive synthetic set, so bytes-per-flow
from live traffic (≈ 30 B/flow measured in Phase 3 on the real store) is the number to plan with.

## Debug build (`swift test`, unoptimized, 2026-09-11)

| ID | Benchmark | Result | Target | OK |
|---|---|---|---|---|
| P1-decode | IPFIX decode + normalize, 50k records in 2.5k datagrams | 156,315 flows/s | ≥ 5,000 flows/s | ✅ |
| P1-ingest | decode + enrich + stage + Parquet flush, 100k flows | 30,036 flows/s; 2.7 B/flow (synthetic) | ≥ 5,000 flows/s | ✅ |
| P5 | Hour compaction of 60 minute segments (~60k rows) | 1.8 s | < 60 s | ✅ |
| P7 | Overview series + totals over 30 days from 86,400 minute rollups | 24 ms | < 500 ms | ✅ |
| P8 | Which internal devices talked to one external IP (pruned scan, 100k flows) | 27 ms | < 5 s | ✅ |
| P14 | Flows page fetch (500 rows) over a 100k-flow store, first / next page | 215 ms / 262 ms | < 150 ms | see release |

## Release build

`swift test -c release` crashes inside `duckdb-swift` column reads (`ResultSet.element`) for every DuckDB-backed
test, while the same code compiled as a plain optimized executable (`swift run -c release nsprobe`, 100k flows
written, flushed and read back; also under Address Sanitizer) and the Xcode Release build of the collector run
correctly. The failure is therefore tied to the `-enable-testing` test bundle build, not to shipped binaries;
the benchmark suite is run in debug mode and the release numbers below come from `Tools/nsprobe`.

| ID | Benchmark (release, `nsprobe`) | Result | Target | OK |
|---|---|---|---|---|
| P14 | Flows page fetch (500 rows) over a 100k-flow store in 200 minute segments, first / next page | 171 ms / 173 ms | < 150 ms | ❌ close; segment count dominates (200 files); after hour compaction the same data is 4 files |
| P8 | Top destinations over the same store (pruned scan) | 37 ms | < 5 s | ✅ |

## Covered by tests and scripts rather than benchmarks

| ID | How |
|---|---|
| P3 | `QueueTests` (bounded queues drop-newest / suspend) and `StorageManagerTests` (persist stall keeps memory bounded) |
| P10 | `Scripts/crash-test.sh` (5 × SIGKILL during writes, clean recovery, gap recorded) — run in Phase 3 |
| P11 | `StorageManagerTests` budget enforcement (retention keeps usage under budget; rollups/alerts intact) |
| P12 | `DiskSafetyTests` (pause below threshold, resume when space returns) |
| P13 | `LiveHub` sampling (≤ 4 batches/s, ≤ 500 records) verified on the live collector in Phase 2 |

## Not yet measured

P2 (burst 20k flows/s over UDP with drop accounting), P4 (concurrent queries during ingest), P6 (cold start with a
12,000-segment manifest), P9 (24 h soak). These need the collector process rather than the package and are listed
in the roadmap.

## Notes

- `SET enable_object_cache = true` (DuckDB's Parquet metadata cache) was measured at 1,000 ms vs 171 ms for the
  same paged query and is therefore left at its default.
- The P14 store above is deliberately pessimistic: 200 one-minute segments. Compaction merges them into hour
  segments after 5 minutes of grace, so a real store of the same size has far fewer files to open.
