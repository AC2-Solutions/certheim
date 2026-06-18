# CSR Dashboard v2.5.0

_Released 2026-06-18. 2 changes since v2.4.0._

## Features

- **release:** generate detailed notes from commit bodies (`51b9b96`)
  The auto-generated CHANGELOG/release notes were one terse line per commit (subject only). Rework
  tools/release.sh to include each commit's body - re-flowed into wrapped, indented paragraphs with
  in-body bullet lists preserved as nested items - grouped into Breaking changes / Features / Fixes
  & improvements / Other, each entry tagged with its short hash, plus a "N changes since vPREV"
  summary line. So every release now reads as real, detailed notes instead of a subject list.

## Fixes & improvements

- **ci:** create the GitLab Release object reliably (api scope + browser UA) (`b1ca16f`)
  The auto-release job pushed tags fine but the GitLab Release *object* step silently warned off for
  v2.3.0/v2.4.0. Two causes:
  - RELEASE_TOKEN had the write_repository scope, which is Git-over-HTTP only and cannot call the
    API, so POST /releases 403'd. Token reissued with the api scope (variable updated out of
    band).
  - The curl had no browser User-Agent, which Cloudflare bot-blocks (1010) on API writes to the
    public host.
  Add -A "Mozilla/5.0" and surface the HTTP status so a future failure isn't silent. Docs updated to
  require the api scope.
