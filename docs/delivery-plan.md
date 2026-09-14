# Phased delivery plan

Each phase ends with: `xcodebuild build`, relevant test targets green (or failures reported
verbatim), a demonstrable vertical slice, and updated docs. No phase substitutes mocks for
unfinished functionality; unfinished paths throw `NotImplemented` errors that surface in the UI.

## Phase 0 — Design ✅ (2026-09-10)

## Phase 1 — Foundation ✅ (2026-09-10)

Delivered: XcodeGen workspace (`project.yml`), `NetSentryKit` package with Core/IPC/IPFIX(stub)/Syslog(stub)/
Persistence/DevTools targets, DuckDB 1.1.3 compiled and linked, SQLite wrapper + v1 migrations + MetaStore,
collector LaunchAgent app (Network.framework UDP/TCP listeners, lock-free receive queue, health monitor with
rates/warnings/gaps, sleep/wake/clock observers, XPC server, graceful shutdown, single-instance lock),
dashboard shell (10 sections, Overview, Collector Health, Settings with SMAppService toggle), `nsgen` CLI,
27 unit tests. Verified on macOS 26.6: registration via SMAppService, launchd crash restart (`kill -9` → new
pid), 3,125 datagrams in 10 s with 0 drops via `nsgen`, XPC status round-trip.
Deviations: ADR-002 (no sandbox in v1). Not yet done from the original Phase 1 list: nothing — IPFIX/syslog
decoding and the Live Activity view are Phase 2 as planned.

Original scope:
1. `project.yml` → workspace with app, collector, packages; ad-hoc signing; DuckDB dependency
   compiled once (verifies build time and binary size on this machine).
2. `NetSentryCore`: `IPAddress` (16-byte, canonical text), `Timestamp` (µs), `FlowRecord`,
   `SyslogEvent`, `ClientRef`, `Origin`, `BoundedQueue` (with tests), `Branding`.
3. `NetSentryIPC`: envelopes, all request/reply types, encode/decode tests.
4. Collector: lifecycle (`main.swift`, signal handling, single-instance lock), `NWListener`
   UDP/TCP with per-listener state machine, receive stage with timestamping, counters, health
   snapshot, XPC listener, sleep/wake and clock-change observers, gap markers (in memory until
   Phase 3).
5. Dashboard shell: sidebar navigation for all 10 sections, Collector Health page live from XPC,
   Settings (collector enablement via `SMAppService`, ports, interfaces), placeholders that state
   "available in Phase N" rather than fake data.
6. Settings persistence (SQLite `config` table + bootstrap JSON).
Exit demo: run collector via Xcode, send UDP with `nsgen`, see counters move in the dashboard.

## Phase 2 — Ingestion ✅ (2026-09-10)

Delivered: IPFIX v10 decoder (templates/options/var-len/PEN/multi-exporter/multi-domain, cache with
refresh/replace/withdraw/expiry, pending-data buffering with bounds and TTL, record-based sequence
tracking, restart detection, clock skew, PSAMP sampling, interface and domain names, NTP/sysUpTime
timestamps, unknown IEs preserved), 146-element IANA registry, fuzz-hardened; syslog RFC 3164/5424
parsing with structured data and year inference, RFC 6587 TCP framing, family parsers (netfilter,
dnsmasq DHCP/DNS, OpenSSH, Suricata fast) with a versioned registry and fallback; collector pipeline
receive → decode → dispatch with a bounded backpressure queue; exporter status, template/pending/
NetFlow-version warnings; diagnostic raw capture; Live Activity view with pause/filter/inspector;
`nsgen ipfix` scenarios. Verified against real UCG Fiber IPFIX (port 2055, sampled 1:512).
Open: UniFi syslog samples (gateway still on port 514); parsers marked unverified until then.

Original scope:
IPFIX v10 decoder (templates, options, var-len, PEN, multi-exporter/domain, cache/expiry/refresh,
restart detection, sequence gaps, skew, sampling, pending-data buffering, health metrics);
syslog framing (UDP, TCP octet-counting and LF), RFC 3164/5424, netfilter k=v parser, UniFi family
parsers behind a registry with versions, fallback parser; decode/enrich queues with backpressure;
fixture-driven tests including fuzzing; `nsgen` generators for every case; Live Activity view
with sampled stream, pause/resume/filter/inspect.

## Phase 3 — Storage ✅ (2026-09-10)

Delivered: DuckDB engine wrapper; Parquet segment writer (in-memory staging via Appender, `COPY … (FORMAT
PARQUET, ZSTD)` to `tmp/`, `F_FULLFSYNC`, atomic rename, SHA-256, manifest row + column stats + minute/hour
rollups in one SQLite transaction); segment manifest API; StorageManager (usage by category, disk-safety
pause/resume with 1 GB hysteresis, retention stages 1/2/3/5 with allocation-weighted deletion, shrink
preview, raw-column stripping, 5-minute aggregation rewrite, minute→hour→day compaction with row-count
verification, startup recovery: tmp cleanup, orphan quarantine, missing/corrupt marking with retry, and
self-healing verification); hot in-memory buffer serving `hot.query`; collector wiring (persist stage, disk-
pressure gaps and warnings, hourly compaction, downtime gap from newest record); IPC `storage.status`,
`retention.preview/run`, `storage.flush`, `segments.verify`; Storage view with category chart and
maintenance actions; Settings shrink-preview sheet; `Scripts/crash-test.sh` (P10). Measured on the live
collector: ≈ 30 bytes per flow record, ≈ 38 bytes per event, five SIGKILLs → five clean restarts, zero
leftovers, all downtime recorded as gaps. 61+ package tests pass.
Open for Phase 6 polish: day-tier `rollup_day` and `daily_summary` writers, backup/restore UI
(per-client rollups landed with Phase 5).

Original scope:
SQLite wrapper + migrations; segment writer (DuckDB → Parquet, atomic finalize); manifest;
hot ring buffer; startup recovery; usage accounting; budget/allocation/threshold enforcement;
retention stages; compaction (minute→hour→day, raw stripping, aggregation); Storage view with
preview-before-shrink; crash-recovery tests (SIGKILL loop); P10–P12 benchmarks.

## Phase 4 — Analytics ✅ (2026-09-11)

Delivered: `NetSentryAnalytics` — typed `RecordFilter`/`FlowQuery`/`EventQuery`/`TopNQuery` model compiled
to DuckDB SQL with bound parameters only; manifest and column-statistics segment pruning; keyset
pagination; top-N by any dimension; time series from minute rollups (record-level filters fall back to
segment scans, both agree in tests); event counts; gap overlay; read-only `ReadEngine` used in-process by
the dashboard (own DuckDB connection per query, never blocks the collector). Dashboard: Overview with
traffic chart (gaps shaded), top clients/destinations/ports/countries/organizations, event and IDS
summaries; Flows table (filters, sort, columns, keyset "load more", inspector, CSV export, saved searches);
Events table (type/severity/action/text filters, raw message, saved searches); provisional IP-based
Clients view with per-client chart and top destinations/ports. 70 package tests pass; live-store check:
one-hour overview aggregates in 274 ms.
Open: day-tier rollups/daily summaries, per-client rollups (after Phase 5 entity resolution), query
cancellation is cooperative (DuckDB interrupt not exposed by duckdb-swift 1.1.3), UI screenshots via
XCUITest (Phase 6).

Original scope:
Typed query model → parameterized SQL; manifest pruning; DuckDB read engine with cancellation;
rollups; Overview; Clients list/detail; Flows table (virtualized, customizable columns, saved
searches); Events views (structured + raw); P4, P7, P8, P14 benchmarks.

## Phase 5 — Security ✅ (delivered)
Delivered:
* `NetSentryEnrichment`: pure-Swift MaxMind DB reader (`MMDBReader`, IPv4/IPv6, 24/28/32-bit records,
  all data types) with a writer in DevTools for fixtures; `ServiceNames`; `EntityResolver` actor
  (clients, address history with validity intervals, MAC and DHCP-hostname learning, rename/tags/
  notes/trust, merge/split, address moves only after 3 consecutive observations of a new MAC so one
  garbled record cannot rewrite history); `Enricher` (version 2: client ids, GeoIP/ASN, service names).
* `NetSentryDetection`: `DetectionRule` protocol with typed, user-editable `RuleParameter`s, findings
  carrying entity, evidence, baseline, referenced record ids, explanation (Markdown) and investigation
  steps; the 15 rules (first-seen destination/country/ASN/service with learning period, unauthorized
  resolver, horizontal/vertical scan, repeated denials, large transfer, unusual volume vs. 14-day p95
  baseline, unusual hour vs. 14-day histogram, beaconing by interval regularity, unexpected VLAN pair,
  IDS event correlated with flows on both endpoints, collection failure from health); `AlertStore`
  (dedupe/occurrence counting, states, notes, suppressions with scopes and expiry, expectations,
  per-rule configuration, rule state and first-seen tables); `DetectionEngine` actor with policy reload.
  Migration v2 rebuilds `alerts` without the client foreign key.
* `NetSentryCorrelation`: `TimelineBuilder` producing one chronological timeline from flows, events,
  alerts, annotations and gaps for a flow/event/client/address/alert/range anchor with observational
  relations only ("same client", "same address", "within 3 s"); never causal language.
* Collector: enrichment after classification, detection per batch plus health-based detection every
  10 s, alert notifications (`UNUserNotificationCenter`, deep link `netsentry://alert/<id>`; the
  dashboard posts instead when the collector process cannot), `security.op` XPC operations for alerts,
  suppressions, expectations, rules and clients; per-client minute rollups.
* Dashboard: Security view (filters, evidence, explanation, baseline, notes, acknowledge/resolve/
  reopen, suppress and mark-expected from the alert, rule editor), Investigation view (window ±5 min to
  ±24 h, kind filters, pivots), Clients view keyed by identity (rename, tags, notes, trust, merge,
  split, expectations, alerts, traffic), Settings (GeoIP import, global expectations, suppressions).
* Tests: MMDB reader, resolver (incl. hysteresis), enricher, 12 rule tests, migration v2, 3 timeline
  tests; 91 package tests pass.

Verified on the development Mac against the live UCG Fiber: identities resolved from IPFIX MACs,
detection batches running, rules configurable over XPC, synthetic traffic (nsgen) with deterministic
per-client MACs. Notification authorization is denied to the ad-hoc signed dev agent (macOS refuses
`UNUserNotificationCenter` for it), which is why the dashboard fallback exists.

Original scope: entity resolution (DHCP-derived, manual, merge/split, historical addresses); GeoIP/ASN via
`MMDBReader`; correlation engine + Investigation timeline; the 15 detection rules with tests
that trigger each from fixtures; alert workflow (states, suppressions, exceptions, notes);
`UNUserNotificationCenter` with actions deep-linking `netsentry://alert/<id>`.

## Phase 6 — Productization ✅ (delivered; two items need the user's machine)
Delivered so far:
* Setup wizard (storage + budget, gateway instructions with this Mac's addresses and the 514 caveat, login
  item registration, 15 s IPFIX/syslog validation through `listener.test`, DHCP fixed-address warning);
  shown once until `setupCompleted`.
* `NetSentryExport`: `RedactionPolicy`/`Redactor` (salted SHA-256 address tokens applied to fields and free
  text, MAC/hostname/raw/username/note removal), flows/events/alerts CSV+JSON (`netsentry-export/1`),
  incident report (Markdown with timeline), investigation bundle (`netsentry-investigation/1`); export sheet
  with remembered policy; tests. `docs/exports.md`.
* Diagnostics export (`diagnostics.export`) and manifest backup (`storage.backup`) in the collector, with
  buttons in Collector Health and Storage; `Scripts/restore-manifest.sh`.
* Day tier: `rollup_day` and `daily_summary` built after compaction for completed UTC days; tests.
* Release tooling: `Scripts/build-release.sh` (archive, Developer ID export, verification, DMG, notarytool,
  stapling, Gatekeeper assessment; `--dry-run` without a certificate), `docs/release.md` checklist,
  `docs/known-limitations.md`, `docs/roadmap.md`.
* Thread-safe SQLite wrapper (recursive lock + serialized mode) after the Overview loader crashed with
  concurrent manifest queries; stress test added.

* Performance: `Tests/NetSentryBenchmarks` (env-gated) and `Tools/nsprobe` (release, sanitizer-friendly);
  results in `docs/performance-results.md` (decode 156k flows/s, ingest 30k flows/s, compaction 1.8 s, Overview
  24 ms, pruned lookup 27–37 ms, page fetch 171 ms against a 150 ms target on a 200-file store).
* Accessibility pass: decorative icons hidden, status icons labelled, tables named, badges combined, ⌘R/⌘E
  shortcuts on the investigation views.
* XCUITest screenshot suite (`Apps/NetSentryUITests`) wired into the scheme; needs a one-time Automation
  approval on the machine before it can drive the app (see developer-setup gotcha 12).
* Fixed on the way: SQLite wrapper thread-safety (Overview crash), ad-hoc dev agent notifications fall back to
  the dashboard, DuckDB result lifetimes pinned, Timestamp clamped against garbled syslog dates (fuzz crash),
  synthetic MACs made stable per client, address moves need three consecutive observations.

Remaining: XCUITest run on an approved machine; P2/P4/P6/P9 process-level benchmarks (roadmap).

Original scope: setup wizard (with real-traffic validation and DHCP warning); launch-at-login; exports (JSON,
CSV, incident report, investigation bundle) with redaction/hashing; accessibility pass;
performance suite P1–P14; diagnostics export; backup/restore; release scripts; signing and
notarization checklist; UniFi configuration guide; known limitations; roadmap.

## Major risks

| # | Risk | Likelihood / impact | Mitigation |
|---|---|---|---|
| R1 | UCG Fiber IPFIX template contents differ from assumptions (no start/end times, no VLAN, biflow, or sampling only via options) | High / Medium | Decoder is template-driven and keeps unknown IEs; normalization has documented fallbacks; real pcap requested before Phase 2 ends. |
| R2 | UniFi syslog families undocumented and change between releases | High / Medium | Parser registry with versions + reprocessing; fallback keeps every message; fixtures from real device; UniFi version recorded per fixture. |
| R3 | DuckDB build time/size and Swift 6 interop friction | Medium / Medium | Compile in Phase 1 first thing; wrap in one module; fallback plan is SQLite-only columnar-ish storage with reduced targets (documented, not preferred). |
| R4 | App Sandbox + LaunchAgent + custom storage location interactions | Medium / High | Resolved by design (D2); verified in Phase 1 with an external-volume test. |
| R5 | Ad-hoc signing lacks App Group → dev/prod path differences | High / Low | Explicit dev fallback path; integration tests run against both layouts. |
| R6 | 500 GB performance targets unverifiable on a 460 GB internal disk with 26 GB free | High / Medium | Synthetic manifest with sparse Parquet files for startup test; full-scale scan benchmarks run on an external SSD (needs one ≥ 1 TB) or scaled 10× down with extrapolation, clearly labelled. |
| R7 | Sampling misinterpretation inflates/deflates byte counts | Medium / High | Store raw counters and sampling interval separately; UI shows "sampled ×N" badge; never multiply silently. |
| R8 | No Developer ID on this machine → notarization cannot be exercised | Certain / Low | Scripts prepared and dry-run with ad-hoc identity; final run requires the user's certificate. |
| R9 | macOS Local Network privacy prompts or firewall blocking inbound UDP | Medium / High | Wizard detects "no packets received" and explains macOS Firewall settings; listener bind errors surfaced. |

## Before implementation — decisions to confirm

1. **DuckDB as the analytical engine** (ADR D5) — accepts a large source-built dependency.
2. **Sandboxed dashboard + non-sandboxed hardened collector; Developer ID distribution** (D1–D3).
3. **Deployment target macOS 15** (or 26-only if you prefer newer APIs and a smaller matrix).
4. **Port 514 deferred** to the roadmap (D9).
5. **Bundle prefix `com.netsentry`** and your Apple Team ID (needed for App Group and XPC
   requirement strings; placeholder `TEAMID` until provided).
6. Provide the samples in `docs/required-fixtures.md` when convenient; they gate the UniFi
   parsers and rate calibration, not the foundation.
