# Releasing

Versions follow **[Semantic Versioning](https://semver.org)** (`MAJOR.MINOR.PATCH`)
and are cut **automatically by CI** from the commit history. You don't edit
version files or write changelog entries by hand — you write good commit
messages and merge; the release falls out.

## Three editions, three version lines

Certinel ships as three stacked editions on three branches:

```
Community (base)  ->  Commercial  ->  Government
```

Each edition has its **own** version line in its **own** tag namespace and its
**own** files, so a release on one edition never collides with another when a
change propagates upward:

| Edition | Branch | Tag namespace | Version file | Changelog file |
|---|---|---|---|---|
| Community | `Community` | `community-vX.Y.Z` | `editions/community.version` | `editions/community.changelog.md` |
| Commercial | `Commercial` | `commercial-vX.Y.Z` | `editions/commercial.version` | `editions/commercial.changelog.md` |
| Government | `Government` | `government-vX.Y.Z` | `editions/government.version` | `editions/government.changelog.md` |

Because each edition writes only its own files (and **only Community** writes the
root `VERSION`), a bottom-up propagation MR carries one edition's release commits
up **without touching** the higher edition's files — zero release-accounting
conflicts, no custom merge driver required.

The editions therefore **drift apart in MINOR/PATCH** by design — at any time you
might have `community-v4.18.4`, `commercial-v4.22.1`, `government-v4.25.6`. That's
correct: each number tells a customer exactly what's in the build they run.

## The MAJOR is a shared platform generation (cut at Community only)

To keep all three editions on the same major (`v4`, `v5`, …), the **MAJOR
component is owned by the Community/base edition alone**:

- **Community** honors `type!:` / `BREAKING CHANGE` → a real **MAJOR** bump.
- **Commercial** and **Government** **clamp** a breaking change to a **MINOR** —
  they can never bump the major themselves.
- To start a new generation, you cut a major at Community (even if the breaking
  work lives up-tier, anchor a `feat!:` at Community). It then **sweeps upward**
  via propagation, and because a major zeroes minor/patch, every edition
  re-aligns on `vN.0.0`. After that they fan out again on `vN.x.y`.

So: editions re-converge on every Community-cut major, and drift apart on
everything above it.

## How a version is chosen

On every push to **`Community`**, **`Commercial`**, or **`Government`**, the CI
**`release`** job runs `tools/release.sh` for that edition. It inspects the
[Conventional Commit](https://www.conventionalcommits.org) subjects since the
edition's last tag (falling back to the legacy `vX.Y.Z` line for an edition's
very first release, so all three continue from the shared point where they
branched) and picks the bump:

| Commit prefix (since last edition tag) | Bump | Notes |
|---|---|---|
| `feat:` / `feat(scope):` | **MINOR** | a new feature |
| `fix:` / `perf:` / `refactor:` / `build:` / `revert:` | **PATCH** | a bug fix / patch |
| any `type!:` or a `BREAKING CHANGE:` body | **MAJOR** | **Community only**; clamped to MINOR on Commercial/Government |
| only `docs` / `chore` / `ci` / `test` / `style` | **no release** | nothing user-facing |

The job then writes the edition's `editions/<edition>.version` + changelog (and,
for Community, mirrors the number into root `VERSION`), commits
(`release: <edition>-vX.Y.Z [skip ci]`), **tags `<edition>-vX.Y.Z`**, creates a
**GitLab Release** object, and builds + publishes the edition's OCI images
(`<edition>-vX.Y.Z` + the rolling `<edition>` tag; Community also updates the
bare `latest`/`slim`). The transient `RELEASE-NOTES-<edition>-vX.Y.Z.md` used for
the Release description is **gitignored and never committed**.

## So: write Conventional Commits

Your MR's squashed/merge commit subject is what counts. Use:

```
feat(signing): add Windows CA provider
fix(groups): assign a user to multiple groups in one save
feat(api)!: drop the deprecated /v1 endpoints   # ! = breaking -> MAJOR (Community only)
```

## One-time setup (required for the auto-release to push)

The job needs `RELEASE_TOKEN` (an **`api`**-scope, **Maintainer** project access
token, set as a **masked + protected** CI/CD variable) that is **Allowed to
push** to all three protected edition branches. Until it's set, the `release`
job is a **safe no-op**. `[skip ci]` on the release commit prevents a re-trigger,
and the job is idempotent (a tag that already exists → does nothing).

## Forcing a specific version

Bump the edition's `editions/<edition>.version` by hand in your MR to a value
**higher** than the last edition tag; `release.sh` honors a manually-set higher
version and tags that instead of the computed bump.

## The build edition marker

`backend/build_mode.py` carries `EDITION = "community" | "commercial" |
"government"`, which differs per branch and is **not** auto-merged. If a Community
change to `build_mode.py` ever conflicts on that line during propagation, resolve
it by **keeping the target branch's edition value** (Commercial stays
`"commercial"`, Government stays `"government"`). See `.gitattributes`.

## Deploying a release

Tagging doesn't deploy. To roll a tag onto a box: check it out and run
`deploy.sh` there. `deploy.sh` resolves the build's edition, materializes
`editions/<edition>.version` into root `VERSION`, and verifies the running app
reports it.
