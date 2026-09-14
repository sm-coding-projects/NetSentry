# Roadmap

Ordered by expected value for a UniFi household or small office. Items are not commitments.

1. **Syslog fixtures from a real UCG Fiber** for firewall, DHCP, IDS/IPS, VPN and admin-login families, then
   flip the parsers to `verified=true` and add per-family tests (blocked on `docs/required-fixtures.md`).
2. **Daily digest**: a notification and a Overview card built from `daily_summary` (new clients, top talkers,
   alerts, gaps), plus a weekly comparison.
3. **Prevent sleep while collecting** (IOKit power assertion, opt-in) and a menu-bar status item.
4. **GeoIP auto-update** using the stored MaxMind licence key (download + verify + atomic swap).
5. **Demo workspace populate** from inside the collector (the `demo.populate` request) so the wizard can show
   the product without a gateway.
6. **System daemon mode** (SMAppService daemon) for collection independent of login.
7. **Alert forwarding**: webhook and local syslog out, with the same redaction policies as exports.
8. **Long-range Overview from `rollup_day`** and retention of day rollups beyond the flow budget.
9. **XCUITest screenshot suite** driven by the demo workspace for release QA.
10. **Query cancellation** once `duckdb-swift` exposes `interrupt`.
