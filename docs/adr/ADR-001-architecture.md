# ADR-001: NetSentry Architecture Decision Record

Status: **Accepted** 2026-09-10 (D2 superseded by ADR-002)  
Date: 2026-09-10  
Product name: "NetSentry" (see §12 for renaming strategy)

## 1. Context

NetSentry is a privacy-first, local macOS application that receives IPFIX (NetFlow v10) and syslog
from a UniFi Cloud Gateway Fiber (UCG Fiber), stores it within a bounded budget, and provides
investigation, correlation, and explainable detections. It is a local alternative to a SIEM for one
UniFi network.

Environment verified on the build machine:

| Item | Value |
|---|---|
| macOS | 26.6.2 (build 25G83) |
| Xcode | 26.6 (17F113), macOS SDK 26.5 |
| Swift | 6.4 |
| Hardware | Apple M4 Pro, 12 cores, 24 GB |
| Project generator | XcodeGen 2.46.0 (installed) |
| Signing identities | none (ad-hoc signing for development; Developer ID required for release) |
| Dev Mac LAN address | 192.168.99.128 on `en0` (DHCP; see setup wizard warning) |

Deployment target: **macOS 15.0** (Sequoia). Rationale: `SMAppService` (13+), `NSXPCConnection`
code-signing requirements (13+), Swift 6 strict concurrency, `@Observable`, Charts improvements,
App Group validation changes introduced in 15. Building with the macOS 26 SDK.

## 2. Decisions

### D1. Process topology: sandboxed dashboard app + bundled background collector agent

* `NetSentry.app` — SwiftUI dashboard. **App Sandbox enabled.**
* `NetSentryCollector.app` — background-only (`LSUIElement`/`LSBackgroundOnly`) helper app bundle
  embedded inside `NetSentry.app/Contents/Library/`, registered as a **LaunchAgent via
  `SMAppService.agent(plistName:)`** with `BundleProgram`, `KeepAlive: {SuccessfulExit: false}`,
  `ThrottleInterval: 5`, `ProcessType: Adaptive`. Launchd restarts it after a crash; the user
  toggles it in Settings and it appears in System Settings › General › Login Items & Extensions.
* The collector is an **app bundle** rather than a bare executable so it can (a) post
  `UNUserNotificationCenter` notifications under its own bundle ID, (b) receive `NSWorkspace`
  sleep/wake notifications, and (c) carry its own Info.plist, entitlements, and version.
* The collector runs with the **Hardened Runtime but without App Sandbox** (see D2 for why).
* A LaunchAgent starts at *login*, not at boot. With FileVault the volume is only unlocked at login
  anyway, so "at boot" is effectively "at first login". A root LaunchDaemon is deliberately not used
  for v1 because it cannot safely own files in the user's home directory and would require admin
  approval. A daemon variant is on the roadmap for headless Macs.

### D2. Sandboxing split — **superseded by ADR-002** (macOS rejects a sandboxed app registering a non-sandboxed agent)

The dashboard is sandboxed. The collector is not, because:

1. The user may choose a storage location outside the container (external SSD is the common case
   for 250–500 GB budgets). Security-scoped bookmarks are bound to the creating bundle ID and cannot
   be resolved by a second process, so a sandboxed collector could not open the folder the user
   picked in the dashboard.
2. Optional privileged-port support (roadmap) needs a file descriptor handed over from launchd,
   which is simpler outside the sandbox.

Mitigations: hardened runtime, library validation, no JIT, code-signing requirement enforced on the
XPC connection in both directions, all telemetry treated as untrusted (see threat model), and the
collector never executes or interpolates log content.

The dashboard obtains access to a custom storage root via `NSOpenPanel` and stores a
security-scoped bookmark; the collector uses the plain path. Default storage root is
`~/Library/Application Support/NetSentry/Store`, reachable by both processes because neither is
sandboxed (ADR-002); Phase 6 removed the earlier App Group container dependency.

### D3. Distribution: Developer ID + notarization (not Mac App Store) for v1

A non-sandboxed helper is not App Store eligible. Developer ID + notarization is the supported
path. The App Store is a roadmap item requiring a sandboxed collector confined to the group
container.

### D4. IPC: `NSXPCConnection` to the agent's Mach service, versioned Codable envelopes

* Agent plist declares `MachServices: { com.netsentry.collector.xpc: true }`.
* Dashboard connects with `NSXPCConnection(machServiceName:)`; both sides call
  `setCodeSigningRequirement(_:)` with a designated requirement pinned to the Team ID
  (development builds accept ad-hoc signatures only when `DEBUG`).
* The Objective-C protocol surface is intentionally tiny (`send(envelope: Data, reply:)` plus a
  reverse `deliver(envelope: Data)`); all real messages are Swift `Codable` structs in the shared
  `NetSentryIPC` package with an explicit `schemaVersion`. This keeps the contract testable without
  XPC and avoids `NSSecureCoding` classes for every message.
* Live data reaches the UI as **sampled/aggregated batches** (max N records per 250 ms, with
  per-batch "dropped from view" counts), never one message per flow.

### D5. Persistence: SQLite (system) + Parquet segments written and queried by embedded DuckDB

* **SQLite** via the system `libsqlite3` (WAL mode, `synchronous=NORMAL`, foreign keys on) through
  a small in-house wrapper (`NetSentryPersistence/SQLite`). No ORM dependency. Holds
  configuration, exporters, clients, addresses history, tags, alerts, annotations, saved searches,
  parser and rule metadata, first-seen tables, rollups, and the segment manifest.
* **Parquet** (zstd, dictionary-encoded, row groups ≈ 64k rows) for normalized flow and event
  history. Written by the collector using **DuckDB** (`COPY … TO 'x.parquet.tmp'` then atomic
  `rename`) from an in-memory staging table populated with the DuckDB Appender.
* **DuckDB** (`https://github.com/duckdb/duckdb-swift`, product `DuckDB`, built from source with
  the Parquet, JSON, ICU and core-functions extensions statically linked; no extension downloads,
  no network) is the analytical engine in **both** processes: the collector uses it to write
  segments and compute rollups; the dashboard opens its own instance for read-only queries over
  `read_parquet([...])` with file lists taken from the SQLite manifest. Finalized segments are
  immutable, so cross-process reads need no locking.
* **Hot store**: a bounded in-memory ring buffer in the collector (default last 120 s or 200k
  records) that feeds the live view and "just now" investigation queries over XPC, plus
  **minute-tier Parquet micro-segments** flushed every 60 s (or every 50k records). Nothing older
  than ~60 s is ever only in memory. Compaction merges minute segments into hour segments and hour
  segments into day segments. This replaces a separate SQLite hot table, which would have required
  a two-source merge in every query.
* **Rollups** (minute/hour/day) live in SQLite tables keyed by bucket and dimension; they are
  updated by the collector at segment flush time and are the source for long-range charts,
  baselines, and the daily summaries that survive detailed-data deletion.

Dependency justification:

| Dependency | Why | Alternative rejected |
|---|---|---|
| `duckdb-swift` (MIT) | Only maintained embedded engine that both writes and queries Parquet from Swift with zero runtime downloads. Solves columnar writing, compaction (rewrite), column-level size accounting (`parquet_metadata`), and analytics. | Hand-written Parquet writer (weeks of work, no query engine); Apache Arrow Swift (no query engine); SQLite-only (row store, 3–5× larger, slow scans at 500 GB). |
| System `libsqlite3` | Ships with macOS; transactional metadata. | GRDB (fine, but adds a dependency for a thin need). |
| XcodeGen (dev tool only) | Reproducible `.xcodeproj` from `project.yml`; the generated project is committed. | Hand-maintained pbxproj. |

No other third-party code. GeoIP lookup (`MMDBReader`) is implemented in Swift from the public
MaxMind DB format spec. IPFIX, syslog, and RFC parsers are in-house.

Cost accepted: DuckDB compiles ~400 C++ files (first clean build ≈ 8–15 min on M4 Pro; cached
thereafter) and adds ≈ 50–70 MB to each binary that links it.

### D6. Concurrency model

Swift 6 strict concurrency. Pipeline stages are actors connected by bounded `AsyncChannel`-style
queues implemented in `NetSentryCore/BoundedQueue` (no swift-async-algorithms dependency):

```
NWListener(UDP/TCP) ──▶ ReceiveStage (timestamp, enqueue raw datagram)      [bounded 8k datagrams]
                          └─▶ DecodeStage (IPFIX / syslog parsers)           [bounded 32k records]
                                └─▶ EnrichStage (entities, GeoIP, direction) [bounded 32k records]
                                      ├─▶ PersistStage (micro-batch → staging → segment)
                                      ├─▶ DetectionStage (rules on enriched records + rollups)
                                      └─▶ LiveStage (sampler → XPC subscribers)
```

Backpressure policy is explicit per queue: the receive queue **drops newest** (and counts) so the
socket is always drained; decode/enrich queues apply **await-based backpressure** to the previous
stage; persist failures raise a health condition and, if storage is unavailable, pause reception
with a recorded gap marker rather than growing memory.

### D7. Detection engine placement

Detections run inside the collector so alerts are produced while the dashboard is closed. Rules
implement a `DetectionRule` protocol with `name`, `version`, `evaluate(context:) -> [Finding]`,
and declared `parameters`. Rule state (baselines, first-seen sets, suppressions) is in SQLite.
No ML, no global risk score in v1.

### D8. Enrichment data

* GeoIP/ASN: user-supplied `.mmdb` files (MaxMind GeoLite2 or DB-IP Lite). Nothing is bundled;
  optional downloader with a Keychain-stored MaxMind license key, **off by default**.
* Client identity: DHCP syslog leases (when the gateway logs them), ARP is not observable from
  the Mac in general, so the primary sources are DHCP/system events plus manual naming. IP→client
  mapping is versioned by validity interval.
* Service names: bundled IANA port table (static, versioned) — not a network lookup.

### D9. Privileged ports (514) deferred

UniFi allows configuring the remote syslog port and NetFlow port, so unprivileged ports are the
supported path (defaults UDP 4739 IPFIX, UDP/TCP 5514 syslog). Roadmap design for 514: a minimal
`SMAppService.daemon` with a launchd `Sockets` entry (launchd binds 514 as root and passes the
descriptor), running as the unprivileged `_netsentry` user via `UserName`, forwarding the
descriptor to the agent over XPC with `xpc_fd_create`. Not implemented in v1.

### D10. Demo/simulated data isolation

Simulated telemetry is written to a **separate workspace root** (`…/Store-Demo`) selected by a
global "Demo workspace" switch that paints a persistent banner in every view. Additionally, every
record carries `origin` (`live`, `simulated`, `imported`). Both mechanisms are required; the UI
refuses to display two workspaces at once.

### D11. Storage budget semantics

Budget (5–500 GB) is a ceiling on the sum of physical bytes under the storage root. The disk
safety threshold is `max(10 GB, 5 % of volume)` free space. Budget category allocations default to
55/20/10/10/5 and are adjustable. Retention runs in the staged order defined in
`docs/storage-lifecycle.md`. Shrinking the budget never deletes until the user confirms a preview.

### D12. Logging and diagnostics

`os.Logger` with subsystem `com.netsentry.<process>` and categories per module. Telemetry values
are logged as `.private` by default. Diagnostic bundles exclude telemetry unless the user opts in.

## 3. Consequences

* Two DuckDB instances (collector + dashboard) → ~100–200 MB combined baseline memory. Acceptable
  for the target class of machine; measured in benchmarks.
* Because the dashboard reads Parquet directly, the collector's ingestion path is never blocked by
  UI queries. The cost is that the dashboard needs filesystem access to the storage root (D2).
* Not App Store distributable in v1 (D3).
* Real UCG Fiber captures are a hard prerequisite for the UniFi-specific parsers (see
  `docs/required-fixtures.md`). Generic layers (IPFIX, RFC 3164/5424, netfilter `key=value`)
  are built from public specifications and do not depend on them.

## 4. Open questions for the product owner

See the "Before implementation" section of the delivery plan.
