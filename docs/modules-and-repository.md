# Module boundaries and repository structure

## Repository layout

```
NetSentry/
├── project.yml                      # XcodeGen spec → NetSentry.xcodeproj (generated file is committed)
├── NetSentry.xcworkspace/           # workspace: app project + local packages
├── Package.swift                    # umbrella SwiftPM manifest for all local packages (CLI builds, tests)
├── Apps/
│   ├── NetSentry/                   # SwiftUI dashboard (sandboxed)
│   │   ├── App/                     # @main, scenes, window management, deep links (netsentry://)
│   │   ├── Features/                # Overview, LiveActivity, Clients, Flows, Events, Security,
│   │   │                            # Investigation, Storage, CollectorHealth, Settings, Setup
│   │   ├── Components/              # reusable views (tables, charts, filter bars, badges)
│   │   ├── Services/                # CollectorClient (XPC), QueryService, NotificationRouter
│   │   ├── Resources/               # Assets.xcassets, Localizable.xcstrings
│   │   ├── NetSentry.entitlements
│   │   └── Info.plist
│   └── NetSentryCollector/          # background LaunchAgent app bundle (hardened runtime)
│       ├── main.swift               # lifecycle, signal handling, XPC listener
│       ├── CollectorService.swift   # pipeline assembly (receive→decode→enrich→persist→detect→live)
│       ├── LaunchAgent/com.netsentry.collector.plist
│       ├── NetSentryCollector.entitlements
│       └── Info.plist
├── Packages/
│   ├── NetSentryCore/               # domain models, ids, time, IP types, BoundedQueue, Branding
│   ├── NetSentryIPC/                # XPC protocol, Codable envelopes, versioning, code-sign requirement
│   ├── NetSentryIPFIX/              # IPFIX v10 decoder, template cache, exporter/session state
│   ├── NetSentrySyslog/             # RFC 3164/5424 framing + UniFi parsers + fallback parser
│   ├── NetSentryEnrichment/         # entity resolver, MMDBReader (GeoIP/ASN), service names, direction
│   ├── NetSentryPersistence/        # SQLite wrapper, migrations, manifest, segment writer (DuckDB),
│   │                                # retention/compaction, recovery, budget accounting
│   ├── NetSentryAnalytics/          # query builder, DuckDB read engine, rollups, pagination, cancel
│   ├── NetSentryDetection/          # DetectionRule protocol, rules/*, baselines, alert store bridge
│   ├── NetSentryCorrelation/        # timeline assembly, flow↔event matching, explanations
│   ├── NetSentryExport/             # JSON/CSV/report/bundle exporters + redaction
│   └── NetSentryDevTools/           # synthetic generators (IPFIX/syslog), demo data, load tools
├── Tools/
│   └── nsgen/                       # CLI: generate/send IPFIX+syslog, demo workspace, load tests
├── Fixtures/
│   ├── ipfix/                       # .bin datagrams + .json expectations (synthetic + real captures)
│   └── syslog/                      # one .txt per message family (sanitized real samples)
├── Tests/                           # package tests live in each package; integration + UI tests here
│   ├── IntegrationTests/
│   ├── PerformanceTests/
│   └── NetSentryUITests/
├── Scripts/                         # generate-project.sh, build-release.sh, notarize.sh, bench.sh
└── docs/                            # ADRs, schemas, threat model, guides
```

## Package dependency graph (no cycles)

```
NetSentryCore ◀── NetSentryIPC
      ▲            ▲
      ├── NetSentryIPFIX
      ├── NetSentrySyslog
      ├── NetSentryEnrichment
      ├── NetSentryPersistence (depends: Core, DuckDB, libsqlite3)
      ├── NetSentryAnalytics   (depends: Core, Persistence, DuckDB)
      ├── NetSentryDetection   (depends: Core, Persistence, Analytics)
      ├── NetSentryCorrelation (depends: Core, Analytics)
      ├── NetSentryExport      (depends: Core, Analytics, Correlation)
      └── NetSentryDevTools    (depends: Core, IPFIX, Syslog, Persistence)

NetSentryCollector.app → Core, IPC, IPFIX, Syslog, Enrichment, Persistence, Analytics(rollups), Detection
NetSentry.app          → Core, IPC, Persistence(read), Analytics, Correlation, Export, Detection(config types)
```

Rules enforced by the layout:

* Only `NetSentryPersistence` and `NetSentryAnalytics` import DuckDB. Only `NetSentryPersistence`
  touches SQLite.
* Only the two app targets import XPC/AppKit/UserNotifications/ServiceManagement.
* `NetSentryIPFIX` and `NetSentrySyslog` are pure functions of `Data` → records; they have no I/O.
* Views never construct SQL. `NetSentryAnalytics.Query` is a typed, composable filter model that
  compiles to parameterized SQL; all values are bound, never interpolated.
* The detection package has no UI types and no knowledge of XPC.

## Branding

`NetSentryCore.Branding` centralizes `productName`, `bundleIDPrefix` (`com.netsentry`),
`machServiceName`, `appGroupID`, `urlScheme`, `storageFolderName`, and log subsystem prefixes.
`project.yml` defines the same values as `PRODUCT_NAME`/`BUNDLE_PREFIX` settings so a rename is a
change in two files plus asset names.
