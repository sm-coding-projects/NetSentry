# Changelog

All notable changes to NetSentry are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The app version is `MARKETING_VERSION`
in `project.yml`.

## [Unreleased]

## [0.2.3] - 2026-09-29

### Added
- **Adjustable text size.** View › Increase Text Size (⌘+), Decrease Text Size (⌘−) and Actual Size (⌘0)
  scale the text across the dashboard and Settings from 85 % to 200 %; the choice is remembered. The
  sidebar keeps the system sidebar size (System Settings › Appearance › Sidebar icon size).

### Changed
- The detail pane on Live Activity, Flows, Events, Security, Clients and Investigation is now collapsed
  until you select a row, so tables use the full width. Close it with its × button or Escape.

## [0.2.2] - 2026-09-29

### Fixed
- Ad-hoc signed release builds (`build-release.sh --adhoc`) showed "Collector not running": the XPC
  requirement pinned an Apple-anchored Team ID that ad-hoc signatures cannot satisfy. Builds without a
  real Team ID now fall back to the identifier-only requirement.
- Updating an ad-hoc build left the collector unable to start (launchd exit 78, `EX_CONFIG`) because the
  LaunchAgent registration stays pinned to the previous collector's cdhash. The app now re-registers the
  agent on launch whenever the bundled collector changes.

## [0.1.0] - 2026-09-19

First public release. Phases 0–6 delivered.

### Added
- **Flow collection** — IPFIX v10 (NetFlow v10) decoder: templates/options, variable-length and enterprise
  fields, multi-exporter/multi-domain, template refresh/withdraw/expiry, sequence-based loss detection,
  restart & clock-skew detection, PSAMP sampling with a `sampled ×N` badge.
- **Syslog ingestion** — RFC 3164 / RFC 5424 parsing, RFC 6587 TCP framing, family parsers (netfilter,
  dnsmasq DHCP/DNS, OpenSSH, Suricata) with verbatim fallback.
- **Local storage** — DuckDB → Parquet segments (ZSTD, SHA-256), minute/hour/day rollups, hot ring buffer,
  budget-based retention, crash recovery.
- **Dashboard** — Overview, Live Activity, Clients, Flows, Events, Security, Investigation, Storage,
  Collector Health, Settings.
- **Enrichment** — entity resolution, address history, GeoIP/ASN from a user-supplied MaxMind DB.
- **Detection** — 15 deterministic local rules with editable parameters, a full alert workflow, and
  native notifications with `netsentry://alert/<id>` deep links.
- **Investigation** timeline correlating flows, events, alerts, annotations and gaps.
- **Ask AI** — in-app assistant over live local telemetry; OpenAI-compatible and Anthropic-compatible
  providers with configurable base URL/model; API key stored in the macOS Keychain.
- **Exports** — CSV/JSON, Markdown incident reports, investigation bundles, with optional redaction.
- **Packaging** — `Scripts/build-release.sh --adhoc` produces an installable universal (Intel + Apple
  Silicon) DMG without a certificate; the notarized path remains for Developer ID builds.
  `Scripts/publish-release.sh --version <x>` cuts a release locally (build DMG, tag, publish). The GitHub
  Actions `release` workflow auto-builds tagged releases once runners ship Xcode 26.6 (it skips until then).

### Known limitations
- Verified only against the UniFi UCG Fiber. No IPFIX over TCP/SCTP; no NetFlow v5/v9 or sFlow.
- Per-user LaunchAgent; no collection while the Mac sleeps (gaps recorded).
- Prebuilt DMG is a universal binary and not notarized (Gatekeeper bypass required on first launch).

See [`docs/known-limitations.md`](docs/known-limitations.md) for the full list.

[Unreleased]: https://github.com/sm-coding-projects/NetSentry/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sm-coding-projects/NetSentry/releases/tag/v0.1.0
