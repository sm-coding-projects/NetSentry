# Known limitations

Honest list of what NetSentry does not do (yet) and where it depends on things outside its control.

## Telemetry source
- Only the UniFi Cloud Gateway Fiber has been exercised. Its IPFIX export is **sampled** (1:512 was observed);
  byte and packet counts are shown as exported with a "sampled ×N" badge. Sampled counts are never scaled
  silently; the "estimated" toggles multiply by the sampling interval and say so.
- The gateway sends IPFIX templates every few minutes. After a collector restart, data sets arriving before
  the first template are buffered (up to a limit) and decoded when it arrives; a restart therefore loses at
  most the pre-template window, which is recorded as a warning.
- Remote syslog from UniFi OS must be pointed at port 5514 (or any port ≥ 1024): the collector runs as the
  logged-in user and cannot bind 514. The port is editable in Settings › Listeners and in the setup wizard.
  Syslog families are parsed by format families (netfilter, dnsmasq, OpenSSH, Suricata fast, UniFi CEF);
  lines no field parser claims are filed by process name (a fixed table of UniFi gateway, AP and switch
  daemons) with no fields extracted, and anything else is kept verbatim, searchable, and marked unparsed.
  UniFi has not published its syslog formats; the OpenSSH and Suricata-fast parsers carry `verified=false`
  until real fixtures confirm them (netfilter, dnsmasq DHCP, CEF and the wrapper handling are verified).
- IPFIX over TCP/SCTP, NetFlow v5/v9 and sFlow are not supported.

## Platform
- macOS 15 or newer, Apple silicon or Intel. The collector is a per-user LaunchAgent: it runs while the user
  is logged in (including with the screen locked) and stops at logout. Running as a system daemon is a roadmap item.
- Sleep: the Mac stops receiving while asleep. The collector records the gap and the UI shows it; there is no way
  to receive telemetry during sleep. "Prevent sleep while collecting" is a roadmap item.
- Notifications from the collector require a Developer ID signed build; ad-hoc signed development builds are
  refused by the notification service, so the dashboard posts them while it runs.
- The app is not sandboxed (ADR-002); it is distributed outside the App Store.

## Storage and analytics
- The budget is a ceiling, not a reservation. Retention runs after each flush and keeps usage within the
  budget by deleting the oldest raw text, then detailed flows, then hour rollups; minute/day rollups, alerts,
  identities and annotations are never deleted by the budget.
- Queries over very large ranges without a client/address filter scan Parquet segments; DuckDB cannot be
  interrupted mid-query with the pinned `duckdb-swift` 1.1.3, so cancellation is cooperative between segments.
- `swift test -c release` cannot run the DuckDB-backed tests (a crash in `duckdb-swift` column reads that only
  appears in the `-enable-testing` bundle build); optimized executables and the Xcode Release app are unaffected.
  Tests run in debug; release numbers come from `Tools/nsprobe`.
- Day-tier rollups start on the day after installation; the Overview uses minute rollups until then.
- The store is a directory; put it on an encrypted volume (FileVault or an encrypted APFS volume). NetSentry
  does not add its own encryption.

## Detection
- All rules are deterministic and local; there is no threat-intelligence feed and no external lookup unless
  "external lookups" is enabled (nothing uses it yet). GeoIP/ASN require a MaxMind DB file supplied by the user.
- First-seen rules stay silent for the learning period (3 days by default) after a client first appears.
- Beaconing detection needs at least 12 regular contacts within its window; slow beacons (hours) are outside
  the default window and require raising the parameter.
- The IDS rule depends on UniFi's IDS/IPS syslog family being enabled on the gateway.

## Product
- No automatic GeoIP database updates (the MaxMind licence key field exists but the downloader is not wired).
- No multi-gateway topology awareness beyond per-exporter statistics.
- Exports are files; there is no syslog/webhook forwarding of alerts.
- Localization: English only.
