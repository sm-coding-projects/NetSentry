# Changelog

All notable changes to NetSentry are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The app version is `MARKETING_VERSION`
in `project.yml`.

## [Unreleased]

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
  Silicon) DMG without a certificate; the notarized path remains for Developer ID builds. GitHub Actions
  `release` workflow builds and publishes a DMG on every `v*` tag.

### Known limitations
- Verified only against the UniFi UCG Fiber. No IPFIX over TCP/SCTP; no NetFlow v5/v9 or sFlow.
- Per-user LaunchAgent; no collection while the Mac sleeps (gaps recorded).
- Prebuilt DMG is a universal binary and not notarized (Gatekeeper bypass required on first launch).

See [`docs/known-limitations.md`](docs/known-limitations.md) for the full list.

[Unreleased]: https://github.com/sm-coding-projects/NetSentry/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sm-coding-projects/NetSentry/releases/tag/v0.1.0
