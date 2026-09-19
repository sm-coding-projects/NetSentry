#!/bin/zsh
# One-command local release for NetSentry.
#
# Builds an installable universal DMG on this Mac (using the local Xcode toolchain), tags the commit,
# and creates/updates the matching GitHub Release with the DMG and its SHA-256 checksum.
#
# This is the reliable release path today: NetSentry builds with Xcode 26.6, which GitHub-hosted runners
# do not yet ship, so releases are cut locally. The .github/workflows/release.yml workflow takes over
# automatically once the runners provide Xcode 26.6.
#
# Usage:
#   Scripts/publish-release.sh --version 0.2.0                 # ad-hoc DMG, tag v0.2.0, publish release
#   Scripts/publish-release.sh --version 0.2.0 --build 5 --notes-file notes.md
#   Scripts/publish-release.sh --version 0.2.0 --dmg-only      # just build the DMG, no tag/publish
#
# Prerequisites: Xcode (Command Line side handled by DEVELOPER_DIR), xcodegen, and the GitHub CLI (`gh`)
# authenticated with push/release rights on the repo. For a signed & notarized release instead, use
# Scripts/build-release.sh with a Developer ID (see docs/release.md).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=""; BUILD=""; NOTES_FILE=""; DMG_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --build) BUILD="$2"; shift 2 ;;
    --notes-file) NOTES_FILE="$2"; shift 2 ;;
    --dmg-only) DMG_ONLY=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$VERSION" ]] || { echo "--version is required (e.g. --version 0.2.0)" >&2; exit 2; }
[[ -n "$BUILD" ]] || BUILD="$(date +%Y%m%d%H%M)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

echo "==> Building ad-hoc universal DMG for $VERSION (build $BUILD)"
Scripts/build-release.sh --adhoc --version "$VERSION" --build "$BUILD"
DMG="build/release/NetSentry-${VERSION}-universal.dmg"
[[ -f "$DMG" ]] || { echo "expected DMG not found: $DMG" >&2; exit 1; }

if [[ $DMG_ONLY -eq 1 ]]; then
  echo "==> DMG only: $DMG"; exit 0
fi

command -v gh >/dev/null || { echo "gh (GitHub CLI) not found; install it or use --dmg-only" >&2; exit 1; }

TAG="v$VERSION"
if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "==> Tagging $TAG"
  git tag "$TAG"
  git push origin "$TAG"
fi

NOTES_ARGS=(--generate-notes)
[[ -n "$NOTES_FILE" ]] && NOTES_ARGS=(--notes-file "$NOTES_FILE")

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "==> Updating existing release $TAG"
  gh release upload "$TAG" "$DMG" "$DMG.sha256" --clobber
else
  echo "==> Creating release $TAG"
  gh release create "$TAG" "$DMG" "$DMG.sha256" --title "NetSentry $VERSION" --latest "${NOTES_ARGS[@]}"
fi
echo "==> Published: $(gh release view "$TAG" --json url --jq .url)"
