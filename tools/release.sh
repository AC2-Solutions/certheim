#!/usr/bin/env bash
# release.sh - compute the next semantic version from Conventional Commits since
# the last v* tag, and (if a release is warranted) update VERSION, CHANGELOG.md,
# and RELEASE-NOTES-vX.Y.Z.md. The CALLER (the CI `release` job) does the git
# commit + tag + push; this script only computes + writes files.
#
# Bump rules (https://www.conventionalcommits.org + SemVer):
#   * a commit with `<type>!:` OR a `BREAKING CHANGE` body  -> MAJOR (x.0.0)
#   * any `feat:` / `feat(scope):`                          -> MINOR (2.x.0)  <-- new feature
#   * any `fix|perf|refactor|build|revert`                  -> PATCH (2.1.x)  <-- patch
#   * nothing release-worthy (only docs/chore/ci/test/...)  -> no release
# A manually-set VERSION higher than the last tag is honored (force a version).
#
# Output (stdout): the new version "X.Y.Z", or "none" if there's nothing to cut.
# Idempotent: prints "none" (writes nothing) if the target tag already exists or
# the target is already a section in CHANGELOG.md.
set -euo pipefail
cd "$(dirname "$0")/.."

last_tag="$(git describe --tags --match 'v[0-9]*' --abbrev=0 2>/dev/null || true)"
if [ -z "$last_tag" ]; then last_tag="v0.0.0"; range="HEAD"; else range="${last_tag}..HEAD"; fi
lv="${last_tag#v}"; IFS=. read -r LMAJ LMIN LPAT <<<"$lv"
LMAJ="${LMAJ:-0}"; LMIN="${LMIN:-0}"; LPAT="${LPAT:-0}"

subjects="$(git log --no-merges --pretty='%s' "$range" 2>/dev/null || true)"
bodies="$(git log --no-merges --pretty='%B'  "$range" 2>/dev/null || true)"

bump=""
if printf '%s\n' "$bodies" | grep -qE 'BREAKING CHANGE' \
   || printf '%s\n' "$subjects" | grep -qE '^[a-z]+(\([^)]+\))?!:'; then
  bump=major
elif printf '%s\n' "$subjects" | grep -qE '^feat(\([^)]+\))?:'; then
  bump=minor
elif printf '%s\n' "$subjects" | grep -qE '^(fix|perf|refactor|build|revert)(\([^)]+\))?:'; then
  bump=patch
fi

case "$bump" in
  major) target="$((LMAJ+1)).0.0" ;;
  minor) target="${LMAJ}.$((LMIN+1)).0" ;;
  patch) target="${LMAJ}.${LMIN}.$((LPAT+1))" ;;
  *)     echo "none"; exit 0 ;;
esac

# Honor a manually-set higher VERSION (lets a maintainer force a target).
cur="$(cat VERSION 2>/dev/null || echo 0.0.0)"
if [ "$(printf '%s\n%s\n' "$cur" "$target" | sort -V | tail -1)" = "$cur" ] && [ "$cur" != "$target" ]; then
  target="$cur"
fi

# Already released? (tag exists, or already a CHANGELOG section)
if git rev-parse "v$target" >/dev/null 2>&1 || grep -qE "^## ${target//./\\.}( |\$)" CHANGELOG.md 2>/dev/null; then
  echo "none"; exit 0
fi

# --- group commit subjects into release-notes sections ---
strip() { sed -E 's/^[a-z]+(\(([^)]+)\))?(!)?:[[:space:]]*/- (\2) /; s/^- \(\) /- /'; }
feats="$(printf '%s\n' "$subjects" | grep -E '^feat(\([^)]+\))?(!)?:' | strip || true)"
fixes="$(printf '%s\n' "$subjects" | grep -E '^(fix|perf|refactor|build|revert)(\([^)]+\))?(!)?:' | strip || true)"
date="$(date -u +%Y-%m-%d)"

block="$(
  echo "## ${target} — ${date}"
  echo
  if [ -n "$feats" ]; then echo "### Added / Changed"; echo "$feats"; echo; fi
  if [ -n "$fixes" ]; then echo "### Fixed";          echo "$fixes"; echo; fi
)"

# Prepend the block to CHANGELOG.md (after the intro, before the first "## ").
awk -v blk="$block" '
  !done && /^## / { print blk; print ""; done=1 }
  { print }
  END { if (!done) { print ""; print blk } }
' CHANGELOG.md > CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md

# Per-release notes file.
{
  echo "# CSR Dashboard v${target}"
  echo
  echo "_Released ${date}. Auto-generated from the commits since ${last_tag}._"
  echo
  [ -n "$feats" ] && { echo "## Added / Changed"; echo "$feats"; echo; }
  [ -n "$fixes" ] && { echo "## Fixed";           echo "$fixes"; echo; }
} > "RELEASE-NOTES-v${target}.md"

echo "$target" > VERSION
echo "$target"
