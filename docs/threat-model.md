# Threat model

## Assets
Telemetry (who talked to whom), device names/notes, alerts, GeoIP license key, the Mac's
availability (disk, memory, CPU), and the integrity of findings.

## Process protection
Neither process is sandboxed in v1 (ADR-002); both use the hardened runtime. Mitigations below
are therefore the primary defense against malicious telemetry.

## Trust boundaries
1. **LAN → collector sockets.** Anyone on the LAN (or anything that can spoof the gateway's
   address) can send UDP to the listener ports. All IPFIX and syslog input is untrusted.
2. **Collector ⇄ dashboard XPC.** Both processes are ours but verify each other's code signature.
3. **Storage root on disk.** Protected by POSIX permissions (0700 directories, 0600 files) and
   FileVault. Data on an external volume inherits that volume's protection; the UI warns if the
   chosen volume is not encrypted (`diskutil apfs` / `DADiskCopyDescription` check).
4. **Optional outbound connections** (GeoIP database download, future threat intel) — off by
   default; each shows exactly what leaves the Mac.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Malformed IPFIX (bad lengths, huge var-len fields, template with 10k fields, recursive options) | Decoder is bounds-checked at every read, caps: 256 fields/template, 64 KiB datagram, 1024 templates per domain, 8 MiB pending-undecodable buffer per exporter with LRU eviction. Fuzz tests (random mutation of fixtures) must never crash. |
| Template poisoning by a spoofed exporter (fake template id from another source) | Templates are keyed by (source address, observation domain, template id). Optional allow-list of exporter addresses (setup wizard records the detected one; "accept only from these addresses" default on after setup). |
| Syslog flood / amplification (millions of lines) | Bounded receive queue drops newest and counts; per-source rate accounting; max line 8 KiB (excess truncated and flagged); TCP: max 64 connections, idle timeout, 1 MiB per-connection buffer. |
| Log injection (terminal escapes, HTML, `--` for SQL, format strings) | Content is never executed, never interpolated into SQL (bound parameters only, including in DuckDB), rendered as plain text in SwiftUI (no attributed-string parsing of telemetry), control characters escaped in exports and diagnostics. |
| Path traversal via hostnames or exporter names in segment paths | Segment paths are generated from timestamps and sequence numbers only. |
| Resource exhaustion of disk | Budget + safety threshold + pause; SQLite WAL checkpointed at 64 MB; exports counted. |
| Memory exhaustion | Every queue bounded; staging batches capped; DuckDB `memory_limit` set (collector 512 MB, dashboard 1 GB) with spill disabled in the collector. |
| Malicious dashboard client impersonation | XPC code-signing requirement; Mach service is per-user (LaunchAgent) so other users cannot connect. |
| Tampering with stored segments | SHA-256 in manifest; verify on demand and sampled on startup. Not a defense against a root attacker (out of scope). |
| Privilege escalation | Nothing runs as root in v1. Roadmap 514 helper runs as an unprivileged user with launchd-owned sockets. |
| Data exfiltration by the app | No network client code in v1 except the opt-in GeoIP downloader (`URLSession`, pinned to the configured host, documented in the privacy sheet). Network listeners bind only. |
| Secrets | MaxMind key in Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). No other secrets. |
| Diagnostics leaking telemetry | Diagnostic bundle contains counters, config (redacted), logs with `.private` values elided; telemetry samples only with an explicit checkbox. |
| Clock manipulation of the exporter | Per-exporter skew is measured (export_time vs received_at); records store both; queries use received_at for gap logic and start/end for flow logic. Large jumps produce a health warning. |

## Non-goals
Protecting against a compromised macOS user session or root; protecting against an attacker who
controls the gateway (they can send anything, but cannot make NetSentry execute it).
