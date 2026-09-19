#!/bin/zsh
# Release build, Developer ID signing, notarization and DMG packaging for NetSentry.
#
# Usage:
#   Scripts/build-release.sh --team-id ABCDE12345 --identity "Developer ID Application: Name (ABCDE12345)" \
#                            [--notary-profile netsentry-notary] [--version 1.0.0] [--build 42] [--skip-notarize]
#   Scripts/build-release.sh --dry-run          # ad-hoc signed release build, no notarization (CI smoke test)
#   Scripts/build-release.sh --adhoc --version 0.1.0   # ad-hoc signed Release + DMG, no Developer ID / no notarization
#
# --adhoc produces an installable universal (Intel + Apple Silicon) DMG without an Apple Developer
# certificate. The result is NOT
# notarized, so on first launch macOS Gatekeeper shows a warning; the recipient opens it via right-click ->
# Open, or clears quarantine with `xattr -dr com.apple.quarantine /Applications/NetSentry.app`.
#
# Prerequisites (see docs/release.md): Xcode 16+, xcodegen, a Developer ID Application certificate in the login
# keychain, and `xcrun notarytool store-credentials <profile>` run once with an App Store Connect API key or
# Apple ID app-specific password.
set -euo pipefail
cd "$(dirname "$0")/.."

TEAM_ID=""; IDENTITY=""; PROFILE=""; VERSION=""; BUILD=""; DRY_RUN=0; ADHOC=0; SKIP_NOTARIZE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --team-id) TEAM_ID="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --notary-profile) PROFILE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --build) BUILD="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --adhoc) ADHOC=1; shift ;;
    --skip-notarize) SKIP_NOTARIZE=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ $DRY_RUN -eq 0 && $ADHOC -eq 0 && ( -z "$TEAM_ID" || -z "$IDENTITY" ) ]]; then
  echo "--team-id and --identity are required unless --dry-run or --adhoc" >&2; exit 2
fi

OUT="build/release"; ARCHIVE="$OUT/NetSentry.xcarchive"; EXPORT="$OUT/export"
rm -rf "$OUT"; mkdir -p "$OUT"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

echo "==> Generating project"
Scripts/generate-project.sh >/dev/null

SETTINGS=()
[[ -n "$VERSION" ]] && SETTINGS+=("MARKETING_VERSION=$VERSION")
[[ -n "$BUILD" ]] && SETTINGS+=("CURRENT_PROJECT_VERSION=$BUILD")
if [[ $DRY_RUN -eq 1 || $ADHOC -eq 1 ]]; then
  SETTINGS+=("CODE_SIGN_IDENTITY=-" "CODE_SIGN_STYLE=Manual" "DEVELOPMENT_TEAM=" "NETSENTRY_TEAM_ID=TEAMID")
else
  SETTINGS+=("CODE_SIGN_IDENTITY=$IDENTITY" "CODE_SIGN_STYLE=Manual" "DEVELOPMENT_TEAM=$TEAM_ID" "NETSENTRY_TEAM_ID=$TEAM_ID" "OTHER_CODE_SIGN_FLAGS=--timestamp")
fi

echo "==> Archiving (Release)"
xcodebuild -project NetSentry.xcodeproj -scheme NetSentry -configuration Release -archivePath "$ARCHIVE" \
  -derivedDataPath build/DerivedDataRelease "${SETTINGS[@]}" archive | grep -E "error:|warning: .*(sign|entitle)|ARCHIVE (SUCCEEDED|FAILED)" || true
[[ -d "$ARCHIVE/Products/Applications/NetSentry.app" ]] || { echo "archive failed" >&2; exit 1; }

APP="$ARCHIVE/Products/Applications/NetSentry.app"
if [[ $DRY_RUN -eq 0 && $ADHOC -eq 0 ]]; then
  echo "==> Exporting with Developer ID"
  cat > "$OUT/exportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>developer-id</string>
  <key>teamID</key><string>$TEAM_ID</string>
  <key>signingStyle</key><string>manual</string>
  <key>signingCertificate</key><string>Developer ID Application</string>
</dict></plist>
PLIST
  xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportOptionsPlist "$OUT/exportOptions.plist" -exportPath "$EXPORT" | grep -E "error:|EXPORT (SUCCEEDED|FAILED)" || true
  APP="$EXPORT/NetSentry.app"
fi
[[ -d "$APP" ]] || { echo "export failed" >&2; exit 1; }

echo "==> Verifying signatures"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign --verify --strict --verbose=2 "$APP/Contents/Library/NetSentryCollector.app"
codesign -d --entitlements :- "$APP" | grep -q "com.apple.security.app-sandbox" && { echo "ERROR: app must not be sandboxed (ADR-002)" >&2; exit 1; }
codesign -d -vv "$APP" 2>&1 | grep -E "Identifier|TeamIdentifier|Runtime" || true
plutil -p "$APP/Contents/Library/LaunchAgents/com.netsentry.collector.plist" | grep -E "BundleProgram|Label"

if [[ $DRY_RUN -eq 1 ]]; then
  echo "==> Dry run complete: $APP (ad-hoc signed, not notarized)"; exit 0
fi

if [[ $ADHOC -eq 1 ]]; then
  echo "==> Packaging ad-hoc DMG (universal, NOT notarized)"
  DMG="$OUT/NetSentry-${VERSION:-dev}-universal.dmg"; STAGE="$OUT/dmg"
  mkdir -p "$STAGE"; cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
  hdiutil create -volname "NetSentry ${VERSION:-dev}" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
  codesign --force --sign - "$DMG"
  shasum -a 256 "$DMG" | tee "$DMG.sha256"
  echo "==> Done (ad-hoc, not notarized): $DMG"
  echo "    Recipients must clear quarantine: xattr -dr com.apple.quarantine /Applications/NetSentry.app"
  exit 0
fi

echo "==> Packaging DMG"
DMG="$OUT/NetSentry-${VERSION:-dev}.dmg"; STAGE="$OUT/dmg"
mkdir -p "$STAGE"; cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "NetSentry" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
codesign --sign "$IDENTITY" --timestamp "$DMG"

if [[ $SKIP_NOTARIZE -eq 0 ]]; then
  [[ -n "$PROFILE" ]] || { echo "--notary-profile required for notarization (or pass --skip-notarize)" >&2; exit 2; }
  echo "==> Notarizing (this waits for Apple)"
  xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait
  echo "==> Stapling"
  xcrun stapler staple "$DMG"
  xcrun stapler staple "$APP"
  echo "==> Gatekeeper assessment"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
  spctl --assess --type execute --verbose=2 "$APP"
fi
shasum -a 256 "$DMG" | tee "$DMG.sha256"
echo "==> Done: $DMG"
