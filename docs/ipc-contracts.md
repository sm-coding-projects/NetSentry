# IPC contracts (dashboard ⇄ collector)

Transport: `NSXPCConnection` to Mach service `com.netsentry.collector.xpc` (declared in the
LaunchAgent plist). One connection per dashboard window group; the collector accepts multiple
clients (dashboard, `nsgen` in DEBUG only).

Security:
* Both peers call `setCodeSigningRequirement("anchor apple generic and certificate leaf[subject.OU] = \"<TEAMID>\" and identifier \"com.netsentry.*\"")`.
  Debug builds accept the ad-hoc designated requirement of the same build.
* Every message is a `Data` payload containing a JSON-encoded `IPCEnvelope`. The collector rejects
  envelopes above 4 MiB, unknown `kind`, or `schemaVersion` outside its supported range.
* No file paths supplied by the client are opened by the collector except the storage root, which
  is validated to be a directory the collector already knows from its configuration store.

```swift
@objc protocol CollectorXPCProtocol {           // exported by the collector
    func send(_ envelope: Data, reply: @escaping (Data) -> Void)
}
@objc protocol CollectorClientXPCProtocol {     // exported by the dashboard (reverse channel)
    func deliver(_ envelope: Data)
}

struct IPCEnvelope: Codable { let schemaVersion: Int /* 1 */; let requestID: UUID; let kind: String; let payload: Data }
```

## Requests (dashboard → collector) and replies

| kind | Payload | Reply |
|---|---|---|
| `status.get` | – | `CollectorStatus` (version, uptime, listeners, exporters, queue depths, counters, storage summary, current gap state) |
| `health.get` | – | `HealthSnapshot` (all counters + last-N warnings) |
| `config.get` / `config.apply` | `CollectorConfiguration` | `ApplyResult` (per-field accepted/rejected with reason; restarts listeners as needed) |
| `listener.test` | `{ kind: ipfix\|syslog, seconds }` | `ListenerTestResult` (packets seen, first source, templates seen) — used by the setup wizard |
| `live.subscribe` | `LiveSubscription { kinds, filter, maxPerSecond }` | `SubscriptionID`; batches arrive on reverse channel as `live.batch` |
| `live.unsubscribe` | `SubscriptionID` | – |
| `hot.query` | `HotQuery { range, filter, limit }` | `HotQueryResult` (records from the in-memory ring buffer for the last ≤ 120 s) |
| `retention.preview` | `StorageBudget` | `RetentionPreview` (what would be deleted, per category, oldest surviving timestamp) |
| `retention.run` | `{ confirmToken }` | `RetentionResult` |
| `storage.status` | – | `StorageStatus` (usage by category, physical/logical, oldest/newest, compaction state, integrity summary) |
| `segments.verify` | `{ segmentIDs? }` | `VerifyResult` |
| `events.reprocess` | `{ range, parserName? }` | job id; progress via `job.progress` |
| `diagnostics.export` | `{ includeTelemetry: Bool }` | `{ path }` of a zip under `<Store>/diagnostics` (health, configuration without secrets, storage status, verification, manifest usage, 7-day gaps, detection stats, system facts, 2 h of log; with telemetry: newest raw capture ≤ 50 MB and a manifest backup) |
| `storage.backup` | – | `{ path, bytes }` of a zip under `<Store>/backups` with an online SQLite backup of `meta.sqlite` and `collector.json` |
| `demo.populate` (DEBUG/dev-tools) | `DemoSpec` | job id |
| `shutdown.graceful` | – | ack after queues drained |
| `security.op` | `SecurityRequest { op, args: [String: String] }` | `{ json }` — generic JSON so the IPC module stays independent of the detection package. Ops: `alerts.list/get/counts/setState/addNote`, `suppressions.list/add/remove`, `expectations.list/add/remove`, `rules.list/set` (`enabled`, `param.<key>`), `clients.list/get/rename/setNotes/setTags/setTrusted/merge/split`, `detection.stats`. Mutations reload the detection policy immediately. |

## Notifications (collector → dashboard, reverse channel)

| kind | Payload |
|---|---|
| `live.batch` | `LiveBatch { subscriptionID, flows: [FlowRecord], events: [SyslogEvent], sampledOut: Int, generatedAt }` (≤ 500 records, ≤ 4 per second) |
| `health.changed` | `HealthDelta` (listener up/down, exporter seen, template missing, gap opened/closed, storage warnings, drops) |
| `alert.raised` | `AlertRaised { id, title, summary, severity, isNew, clientID, notified }` — `notified` is true when the collector already posted a user notification, so the dashboard does not repeat it |
| `storage.warning` | `StorageWarning { level, reason, freeBytes, budgetBytes }` |
| `job.progress` | `JobProgress { id, fraction, message }` |

## Configuration document

`CollectorConfiguration` (Codable, stored in SQLite `config` table and mirrored to
`~/Library/Application Support/NetSentry/collector.json` for pre-DB bootstrap):

```
enabled, launchAtLogin, storageRoot (path), storageBookmark (dashboard-only),
budgetBytes, allocation {flows, events, raw, meta, reserve}, safetyThreshold {mode: auto|fixed, bytes},
listeners: [{ kind: ipfix|syslog, transport: udp|tcp, port, interface: any|<bsdName>, enabled }],
internalNetworks: [CIDR], trustedResolvers: [IP], expected: {countries, asns, ports…} (per client in DB),
geoip: { cityPath?, asnPath?, autoUpdate: false, licenseKeyRef: keychain },
privacy: { externalLookupsEnabled: false, exportRedactionDefaults },
liveSampling: { maxPerSecond: 200 }, hotBuffer: { seconds: 120, maxRecords: 200_000 },
demoWorkspace: false, diagnosticsLevel
```

Every change is versioned (`config_history` table) so the health view can show "ports changed at".
