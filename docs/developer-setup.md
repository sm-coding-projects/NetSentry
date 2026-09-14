# Developer setup

## Requirements
* macOS 15+, Xcode 26.x (`sudo xcode-select -s /Applications/Xcode.app` or export `DEVELOPER_DIR`).
* XcodeGen (`brew install xcodegen`) — regenerates `NetSentry.xcodeproj` from `project.yml`.
* No Apple Developer account is needed for development: everything is ad-hoc signed.

## Build
```bash
./Scripts/generate-project.sh                       # project.yml → NetSentry.xcodeproj
swift build && swift test                           # packages + unit tests (DuckDB compiles once, ~1–15 min)
xcodebuild -project NetSentry.xcodeproj -scheme NetSentry -configuration Debug -derivedDataPath build/DerivedData build
```
Xcode: open `NetSentry.xcodeproj`, scheme `NetSentry`, run. The collector is embedded in the app at
`Contents/Library/NetSentryCollector.app` and registered with launchd from Settings (or with
`NetSentry.app/Contents/MacOS/NetSentry --register-collector` in Debug builds).

## Developer tools
* `swift run nsgen syslog --port 5514 --count 1000 --rate 200 --style mixed` — send sample syslog (UDP; `--tcp` for TCP).
* `swift run nsgen raw --port 4739 --count 1000 --bytes 150` — raw datagrams for the receive path (IPFIX generation arrives in Phase 2).
* `Scripts/dev-agent.sh dev-install|dev-restart|dev-uninstall` — development LaunchAgent; `register|unregister|reinstall|status|logs|stream` — SMAppService path.
* Debug-only app flags also include `--dump-live out.json [--after s]` (subscribes to the sampled live stream and writes a summary),
  `--dump-overview out.json`, `--verify-storage out.json`, `--dump-security out.json` (alerts, clients, rules,
  detection stats) and `--security-op out.json <op> key=value…` (any `security.op`, e.g.
  `rules.set name=first-seen-destination param.learningDays=0` to exercise first-seen rules without waiting three days),
  `--export-diagnostics out.json` and `--backup-store out.json` (run the collector-side zips and report their paths).
* `swift run -c release nsgen ipfix --scenario multi --seconds 10 --rate 300` — synthetic UCG-shaped IPFIX with
  deterministic per-client MACs (identity resolution sees stable devices).
* Diagnostic capture: set `diagnosticCapture.enabled` in `~/Library/Application Support/NetSentry/collector.json`
  (or Settings, Phase 6) to record raw datagrams to `<Store>/captures/*.nsraw` (format: `RawCaptureFormat`).
* Debug-only app flags: `--register-collector`, `--unregister-collector`,
  `--dump-status out.json [--after s]` (writes the collector's health snapshot and configuration over XPC; the
  basis for scripted end-to-end checks). Offscreen rendering of the SwiftUI window (cacheDisplay, CALayer
  render, ImageRenderer) produces blank images on macOS 26, so visual checks use XCUITest screenshots (Phase 6).

## Logs
```bash
/usr/bin/log stream --predicate 'subsystem BEGINSWITH "com.netsentry"' --style compact --info
/usr/bin/log show --last 5m --predicate 'process == "smd" OR process == "backgroundtaskmanagementd"'   # SMAppService decisions
```
Use `/usr/bin/log` explicitly if your shell aliases `log`.

## Gotchas found while bringing up Phase 1
1. **`SMAppService` requires the app and the agent to share sandbox state.** Registration of a
   non-sandboxed agent from a sandboxed app fails with `Operation not permitted`; the reason is only
   in the `smd` log. See ADR-002.
2. **A stale `~/Library/Containers/<app bundle id>` makes BackgroundTaskManagement treat the app as
   sandboxed** even after the sandbox entitlement is removed, with the same error. Delete the
   container directory in Finder (the terminal cannot; container metadata is protected) or build
   under a different bundle identifier (`NETSENTRY_APP_BUNDLE_ID`).
3. **Any change to the app bundle after registration** (rebuild in place) makes launchd kill the new
   agent at spawn: the crash report says `SIGKILL (Code Signature Invalid)` / `Launch Constraint
   Violation`, launchd reports `EX_CONFIG`, and BackgroundTaskManagement keeps the stale record for a
   while. `Scripts/dev-agent.sh reinstall` retries with `launchctl bootout`, but the reliable
   development loop is `Scripts/dev-agent.sh dev-install` (a plain launchd agent pointing at the
   built binary, no launch constraints) plus `dev-restart` after each rebuild. Use `reinstall`
   only to re-verify the SMAppService path; run `dev-uninstall` before that.
4. **`open -W -a App --args …` reuses a running instance** and waits forever; always pass `-n`
   for the developer flags.
5. **Code-signing requirement strings have no wildcard for `identifier`.** Each side pins the
   other's exact bundle identifier; release builds add the Team ID anchor.
6. **No App Group container is used.** Both builds keep configuration and the default store under
   `~/Library/Application Support/NetSentry/` (`StorageLocations`). The Release build originally resolved an App
   Group container first; with the `TEAMID` placeholder the collector blocked inside `containerURL(...)` before
   logging anything, which is why the dependency was removed.
7. Launching the app binary directly from a non-GUI shell may never create a window; use `open -n -a`.
8. `Logger.debug` lines are not persisted by default; use `.info`/`.notice` for anything you need in `log show`.
10. **Debug builds use the identifier `com.netsentry.app.debug`.** On the development Mac the original
    identifier accumulated per-app OS state (after sandboxed/unsandboxed and SMAppService experiments)
    that left SwiftUI unable to create the main window at all: the scene body was evaluated but
    `NSApp.windows` stayed empty, AppKit logged a window-restoration attempt that returned no window,
    and wiping preferences, saved state and re-registering with LaunchServices did not help, while a
    fresh identifier worked immediately. Release builds keep `com.netsentry.app`.
12. **XCUITest needs a one-time Automation approval.** `xcodebuild test -only-testing:NetSentryUITests` (the
    screenshot suite in `Apps/NetSentryUITests`) fails with "Authentication cancelled. System authentication is
    running" until the test runner is allowed under System Settings → Privacy & Security → Automation /
    Accessibility on the machine; run it once from a logged-in session and approve the prompt. The suite writes
    one PNG per section to `$NETSENTRY_SCREENSHOT_DIR` (default `/tmp/netsentry-screenshots`) and needs the dev
    collector running for data. The UI test bundle is built without the hardened runtime (an ad-hoc signed,
    hardened runner refuses to load an ad-hoc test bundle: "different Team IDs").
13. **Benchmarks**: `NETSENTRY_BENCH=1 swift test -c release --filter Benchmarks` prints a Markdown table
    (`NETSENTRY_BENCH_OUT=file.md` also writes it); see `docs/performance-results.md`.
11. **Notifications from the dev agent are refused** (`UNUserNotificationCenter` reports "Notifications are not
    allowed for this application" for the ad-hoc signed, launchd-plist-installed collector). The collector reports
    `notified=false` in `alert.raised` and the dashboard posts the notification while it runs. Developer ID signed
    builds registered through `SMAppService` are expected to be allowed; verify on the release build.
9. Top-level code in `main.swift` runs on the main actor: never block it with a semaphore while
   awaiting a `Task` (both `nsgen` and the register flag hit this).
