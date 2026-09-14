# Release, signing and notarization

NetSentry ships as a Developer ID signed, notarized, **non-sandboxed** app with the hardened runtime
(see `docs/adr/ADR-002-sandboxing.md` for why the sandbox is off). The collector is an embedded
LaunchAgent (`Contents/Library/NetSentryCollector.app`) registered through `SMAppService`.

## One-time setup

1. Apple Developer Program membership; create a **Developer ID Application** certificate in Xcode
   (Settings → Accounts → Manage Certificates) or at developer.apple.com and install it in the login keychain.
2. Notarization credentials: `xcrun notarytool store-credentials netsentry-notary --apple-id <id> --team-id <TEAMID>`
   (app-specific password) or `--key <AuthKey.p8> --key-id <KEYID> --issuer <ISSUER>` for an App Store Connect API key.
3. Replace the `TEAMID` placeholder: pass `--team-id` to the script (it sets `NETSENTRY_TEAM_ID`, which the XPC
   code-signing requirements and the LaunchAgent plist read at build time). Nothing else in the tree hard-codes the team.
4. `brew install xcodegen`.

## Build

```bash
Scripts/build-release.sh --team-id ABCDE12345 --identity "Developer ID Application: Your Name (ABCDE12345)" \
  --notary-profile netsentry-notary --version 1.0.0 --build 100
```

The script: regenerates the project, archives Release, exports with the developer-id method, verifies both
bundles (`codesign --verify --strict`), refuses a sandboxed entitlement set, checks the LaunchAgent plist,
builds a DMG, notarizes it with `notarytool --wait`, staples both DMG and app, runs `spctl` assessments and
writes a SHA-256 next to the DMG. `--dry-run` produces an ad-hoc signed Release build for CI without a
certificate. Without a Developer ID on the build machine (the situation on the development Mac, risk R8)
the dry run is the furthest the pipeline can be exercised.

## Release checklist

- [ ] `swift test` green; `xcodebuild … build` warning-free for both targets.
- [ ] Bump `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` (both targets share them via `project.yml`).
- [ ] `docs/known-limitations.md` and the roadmap reflect the build.
- [ ] Build with `Scripts/build-release.sh` on a machine with the certificate.
- [ ] On a **clean** macOS user account: mount the DMG, drag to `/Applications`, launch — Gatekeeper must show
      the notarized-app dialog, not a malware warning.
- [ ] First run: setup wizard registers the collector; System Settings → General → Login Items shows
      "NetSentry" with the collector allowed; `launchctl print gui/$UID/com.netsentry.collector` reports running.
- [ ] Notification permission prompt appears for the collector (Developer ID signed agents are allowed to post).
- [ ] Point the UCG Fiber at the Mac (docs/unifi-configuration.md); the wizard's traffic test shows IPFIX
      templates and syslog packets.
- [ ] Kill the collector (`kill -9`); launchd restarts it within seconds; the dashboard shows the gap.
- [ ] Upgrade test: install the previous DMG, then the new one over it; identities, alerts and segments survive
      (migrations run once; check `schema_version` in `meta.sqlite`).
- [ ] Uninstall test: Settings → Background collector off unregisters the agent; the store stays until the
      user removes it.

## Entitlements and hardened runtime

`Apps/NetSentry/Entitlements/NetSentry.entitlements` and the collector's entitlements contain only the
App Group. No `com.apple.security.cs.*` exceptions are needed: the DuckDB and SQLite code is statically
linked Swift/C, no JIT, no unsigned plug-ins. `ENABLE_HARDENED_RUNTIME = YES` for both targets.

## Versioning of on-disk formats

Parquet segment schema, `meta.sqlite` migrations and the export formats (`netsentry-export/1`,
`netsentry-investigation/1`) are versioned independently; a release note must list any bump.
