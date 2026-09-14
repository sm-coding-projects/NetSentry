# Entitlements, signing, sandbox, helper, and distribution constraints

| Target | Sandbox | Hardened runtime | Entitlements |
|---|---|---|---|
| NetSentry.app | no (ADR-002) | yes | `com.apple.security.app-sandbox`, `network.client` (only for opt-in GeoIP download), `files.user-selected.read-write`, `files.bookmarks.app-scope`, `application-groups: group.<TEAMID>.netsentry`, `com.apple.developer.usernotifications.time-sensitive` (optional) |
| NetSentryCollector.app | no | yes | `network.server` is not required outside the sandbox; `application-groups`; no `disable-library-validation` |

* **Team ID** required for the App Group and for XPC code-signing requirements. Dev builds use
  ad-hoc signing (`CODE_SIGN_IDENTITY=-`) and a `DEBUG`-only relaxed XPC requirement; **App Groups
  do not work with ad-hoc signing on macOS 15+**, so dev builds fall back to
  `~/Library/Application Support/NetSentry/` (documented in `docs/developer-setup.md`).
* **SMAppService** requires the agent plist in `Contents/Library/LaunchAgents/` and the executable
  inside the main bundle; the agent and app must share a Team ID. First registration prompts the
  user via System Settings (Login Items). `SMAppService.status` drives the Settings UI.
* **Notarization**: Developer ID Application certificate, `xcrun notarytool`, stapling; the
  collector's nested bundle is signed inside-out. Checklist in `docs/release.md`.
* **No App Store in v1** (non-sandboxed helper).
* **Privileged ports**: not in v1 (see ADR D9). If added, requires an `SMAppService.daemon` and one
  admin approval.
* **Local Network privacy**: receiving on a bound socket does not trigger the local-network
  prompt; sending test packets from `nsgen` to a LAN address might on macOS 15+; the wizard uses
  the loopback interface for self-tests.
