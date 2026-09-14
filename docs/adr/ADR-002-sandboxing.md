# ADR-002: Sandboxing of dashboard and collector

Status: **Accepted** 2026-09-10 — supersedes ADR-001 decision D2.

## Context

ADR-001 proposed a sandboxed dashboard with a hardened-runtime, non-sandboxed collector so the
collector could open a user-chosen storage volume. Registering the agent through `SMAppService`
on macOS 26.6 was rejected by `backgroundtaskmanagementd` with:

```
SMAppService target executable must be sandboxed because the app is sandboxed
```

(`/usr/bin/log show --predicate 'process == "smd" OR process == "backgroundtaskmanagementd"'`).
macOS therefore forces the two processes to share a sandbox state.

The alternatives were:

1. **Both sandboxed.** Storage confined to the App Group container on the boot volume, because a
   security-scoped bookmark created by the dashboard cannot be resolved by the collector (bookmarks
   are app-scoped) and a background agent cannot present an open panel. 250–500 GB budgets on an
   external SSD, an explicit product goal, would be impossible.
2. **Neither sandboxed, hardened runtime only.** Developer ID + notarization distribution, custom
   storage locations work in both processes, `SMAppService` accepts the registration.

## Decision

Option 2 for v1. Both targets: `ENABLE_APP_SANDBOX = NO`, `ENABLE_HARDENED_RUNTIME = YES`, no
library-validation or JIT exemptions, App Group entitlement only (for the shared support
directory when signed with a Team ID).

Compensating controls (see `docs/threat-model.md`):
* all parsing in Swift with bounds checks and caps; fuzz tests are mandatory in Phase 2;
* SQL and DuckDB statements use bound parameters only;
* storage root permissions 0700/0600; no network client code except the opt-in GeoIP download;
* XPC code-signing requirements pinned to the Team ID in release builds.

The App Store variant (both sandboxed, storage in the group container only) remains on the
roadmap; its entitlement files are kept in `Apps/NetSentry/Entitlements/NetSentry-AppStore*.entitlements`.

## Consequences

* v1 is Developer ID only (unchanged from ADR-001 D3).
* `StorageLocations` no longer needs a temporary-exception path in Debug builds.
* Documentation and the threat model are updated to describe both processes as un-sandboxed.
