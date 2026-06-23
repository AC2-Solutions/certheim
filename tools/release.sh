#!/usr/bin/env bash
# release.sh - compute the next semantic version for THIS EDITION from Conventional
# Commits since the edition's last tag, and (if a release is warranted) update the
# per-edition version + changelog files and write a TRANSIENT release-notes file.
# The CALLER (the CI `release` job) commits the edition files, tags, pushes, and
# uses the notes file ONLY to populate the GitLab Release page.
#
# --- Per-edition versioning -------------------------------------------------
# Certinel ships as three stacked editions on three branches:
#     Community (base) -> Commercial -> Government
# Each edition has its OWN version line in its OWN tag namespace and its OWN
# files, so a release on one edition never collides with another on propagation:
#
#   edition      tag namespace        version file              changelog file
#   community    community-v X.Y.Z    editions/community.version  editions/community.changelog.md
#   commercial   commercial-v X.Y.Z   editions/commercial.version editions/commercial.changelog.md
#   government   government-v X.Y.Z   editions/government.version editions/government.changelog.md
#
# Because each edition writes only its own files, a bottom-up propagation MR
# (Community->Commercial->Government) carries one edition's release commits up
# WITHOUT touching the higher edition's files -> zero release-accounting
# conflicts, no custom merge driver required. The root VERSION file is GENERATED
# at deploy/build time from the running edition's file (see deploy.sh); it is
# gitignored and never committed, so it can never diverge either.
#
# --- Major-from-base-only policy --------------------------------------------
# The MAJOR component is a shared "platform generation": vN means the same thing
# in every edition. To keep all editions on the same major, ONLY the Community
# (base) edition may bump the major. A breaking change in premium/government code
# bumps at most a MINOR in that edition; a true new generation is cut by stamping
# a major at Community, which then sweeps upward via propagation (a major zeroes
# minor/patch, so every edition re-aligns on vN.0.0). See RELEASING.md.
#
# Bump rules (https://www.conventionalcommits.org + SemVer):
#   * `<type>!:` OR `BREAKING CHANGE` body  -> MAJOR  (community only; else MINOR)
#   * any `feat:` / `feat(scope):`          -> MINOR
#   * any `fix|perf|refactor|build|revert`  -> PATCH
#   * nothing release-worthy                -> no release
#
# Output (stdout): the new version "X.Y.Z", or "none" if there's nothing to cut.
# Idempotent: prints "none" if the target edition tag already exists or the
# target is already a section in the edition changelog.
set -euo pipefail
cd "$(dirname "$0")/.."

# --- which edition are we releasing? ---------------------------------------
# The CI job sets RELEASE_EDITION from the branch; a local run falls back to the
# build's own marker (backend/build_mode.py), then to community.
ED="${RELEASE_EDITION:-}"
if [ -z "$ED" ]; then
  ED="$(python3 -c 'import sys; sys.path.insert(0,"backend"); import build_mode; print(build_mode.EDITION)' 2>/dev/null || echo community)"
fi
case "$ED" in community|commercial|government) ;; *) ED=community ;; esac
PFX="$ED"
VER_FILE="editions/${PFX}.version"
CL_FILE="editions/${PFX}.changelog.md"
mkdir -p editions

# --- find this edition's last tag (with continuity from the legacy v* line) --
# New namespace is "${PFX}-v*". On the very first per-edition release there is no
# such tag yet, so fall back to the legacy un-prefixed "v*" tag (e.g. v3.20.0) so
# all three editions continue cleanly from the shared point where they branched,
# instead of resetting to 0.0.0.
last_tag="$(git describe --tags --match "${PFX}-v[0-9]*" --abbrev=0 2>/dev/null || true)"
if [ -n "$last_tag" ]; then
  lv="${last_tag#${PFX}-v}"; range="${last_tag}..HEAD"
else
  legacy="$(git describe --tags --match 'v[0-9]*' --abbrev=0 2>/dev/null || true)"
  if [ -n "$legacy" ]; then lv="${legacy#v}"; range="${legacy}..HEAD"; else lv="0.0.0"; range="HEAD"; fi
fi
IFS=. read -r LMAJ LMIN LPAT <<<"$lv"
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

# Major-from-base-only: a non-community edition can never bump the major itself.
# A breaking change up-tier is released as a minor; the major arrives only when a
# Community-cut generation propagates up.
if [ "$bump" = major ] && [ "$PFX" != community ]; then
  echo "note: '$PFX' edition clamps a breaking change to MINOR (majors are cut at Community)." >&2
  bump=minor
fi

case "$bump" in
  major) target="$((LMAJ+1)).0.0" ;;
  minor) target="${LMAJ}.$((LMIN+1)).0" ;;
  patch) target="${LMAJ}.${LMIN}.$((LPAT+1))" ;;
  *)     echo "none"; exit 0 ;;
esac

# Honor a manually-set higher edition version (lets a maintainer force a target).
cur="$(cat "$VER_FILE" 2>/dev/null || echo 0.0.0)"
if [ "$(printf '%s\n%s\n' "$cur" "$target" | sort -V | tail -1)" = "$cur" ] && [ "$cur" != "$target" ]; then
  target="$cur"
fi

# Already released? (edition tag exists, or already an edition changelog section)
if git rev-parse "${PFX}-v$target" >/dev/null 2>&1 \
   || grep -qE "^## ${target//./\\.}( |\$)" "$CL_FILE" 2>/dev/null; then
  echo "none"; exit 0
fi

# --- build detailed release notes from commit subjects AND bodies ----------
export TARGET="$target" LAST_TAG="${last_tag:-}" RANGE="$range" EDITION_PFX="$PFX"
export CL_FILE NOTES_FILE="RELEASE-NOTES-${PFX}-v${target}.md"
export REL_DATE="$(date -u +%Y-%m-%d)"
python3 - <<'PYEOF'
import os, re, subprocess, textwrap

target, last_tag = os.environ["TARGET"], os.environ["LAST_TAG"]
rng, date = os.environ["RANGE"], os.environ["REL_DATE"]
pfx = os.environ["EDITION_PFX"]
cl_file, notes_file = os.environ["CL_FILE"], os.environ["NOTES_FILE"]

raw = subprocess.run(
    ["git", "log", "--no-merges", "--pretty=format:%h%x1f%s%x1f%b%x1e", rng],
    capture_output=True, text=True).stdout

TYPE_RE = re.compile(r'^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<bang>!)?:\s*(?P<desc>.+)$')
TRAILER_RE = re.compile(
    r'^(co-authored-by|signed-off-by|reviewed-by|acked-by|breaking[ -]change)\s*:',
    re.I)

feats, fixes, other, breaking = [], [], [], []
n_user = 0

def clean_body(body):
    blocks, para, li = [], [], None

    def flush_para():
        if para:
            blocks.append(("p", " ".join(para))); para.clear()

    def flush_li():
        nonlocal li
        if li is not None:
            blocks.append(("li", " ".join(li))); li = None

    for ln in body.splitlines():
        s = ln.strip()
        if s == "":
            flush_para(); flush_li(); continue
        if TRAILER_RE.match(s) or "[skip ci]" in s:
            continue
        if re.match(r'^([-*]\s+|\d+[.)]\s+)', s):
            flush_para(); flush_li()
            li = [re.sub(r'^([-*]\s+|\d+[.)]\s+)', '', s)]
        elif li is not None:
            li.append(s)
        else:
            para.append(s)
    flush_para(); flush_li()
    return blocks

for rec in (r for r in raw.split("\x1e") if r.strip()):
    parts = rec.strip("\n").split("\x1f")
    if len(parts) < 2:
        continue
    h, subj = parts[0].strip(), parts[1].strip()
    body = parts[2] if len(parts) > 2 else ""
    if subj.startswith("release:"):
        continue
    m = TYPE_RE.match(subj)
    if not m:
        other.append((h, None, subj, [])); n_user += 1; continue
    t, scope, bang, desc = (m.group("type"), m.group("scope"),
                            m.group("bang"), m.group("desc"))
    entry = (h, scope, desc, clean_body(body))
    n_user += 1
    if bang or re.search(r'^BREAKING[ -]CHANGE', body, re.M):
        breaking.append(entry)
    if t == "feat":
        feats.append(entry)
    elif t in ("fix", "perf", "refactor", "build", "revert"):
        fixes.append(entry)
    else:
        other.append(entry)

def render(entries, with_body=True):
    lines = []
    for h, scope, desc, blocks in entries:
        head = f"- **{scope}:** {desc}" if scope else f"- {desc}"
        lines.append(f"{head} (`{h}`)")
        if with_body:
            for kind, text in blocks:
                if kind == "li":
                    lines.append(textwrap.fill(text, width=98,
                                               initial_indent="  - ", subsequent_indent="    "))
                else:
                    lines.append(textwrap.fill(text, width=100,
                                               initial_indent="  ", subsequent_indent="  "))
    return "\n".join(lines)

def sections(level):
    h = "#" * level
    out = []
    for title, entries, body in (("Breaking changes", breaking, True),
                                 ("Features", feats, True),
                                 ("Fixes & improvements", fixes, True),
                                 ("Other changes", other, False)):
        if entries:
            out.append(f"{h} {title}\n\n{render(entries, body)}\n")
    return "\n".join(out)

label = {"community": "Community", "commercial": "Commercial",
         "government": "Government"}.get(pfx, pfx.capitalize())
since = f"since {last_tag}" if last_tag else "in the initial release"
summary = (f"_Released {date}. {n_user} change" + ("s" if n_user != 1 else "")
           + f" {since}._")

# Per-edition CHANGELOG block (## version), prepended before the first "## ".
block = f"## {target} — {date}\n\n{summary}\n\n{sections(3)}".rstrip() + "\n"
cl = open(cl_file).read().splitlines(keepends=True) if os.path.exists(cl_file) else []
if not cl:
    cl = [f"# Certinel {label} edition — changelog\n", "\n"]
idx = next((i for i, l in enumerate(cl) if l.startswith("## ")), len(cl))
open(cl_file, "w").write("".join(cl[:idx]) + block + "\n" + "".join(cl[idx:]))

# Per-release notes file (# title, ## sections).
notes = f"# Certinel {label} {pfx}-v{target}\n\n{summary}\n\n{sections(2)}".rstrip() + "\n"
open(notes_file, "w").write(notes)
PYEOF

echo "$target" > "$VER_FILE"
# Community is the SOLE writer of the root VERSION file (the base line + the
# dev/deploy fallback). Higher editions never touch it, so it can't diverge or
# conflict on propagation; they carry only their own editions/<ed>.version.
if [ "$PFX" = community ]; then echo "$target" > VERSION; fi
echo "$target"
