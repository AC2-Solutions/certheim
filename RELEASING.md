# Releasing

Versions follow **[Semantic Versioning](https://semver.org)** (`MAJOR.MINOR.PATCH`)
and are cut **automatically by CI** from the commit history. You don't edit
`VERSION` or write changelog entries by hand — you write good commit messages and
merge; the release falls out.

## How a version is chosen

On every push to the default branch (`main`), the CI **`release`** job runs
`tools/release.sh`, which inspects the [Conventional Commit](https://www.conventionalcommits.org)
subjects since the last `v*` tag and picks the bump:

| Commit prefix (since last tag) | Bump | Example |
|---|---|---|
| `feat:` / `feat(scope):` | **MINOR** — `2.1.0 → 2.2.0` | a new feature |
| `fix:` / `perf:` / `refactor:` / `build:` / `revert:` | **PATCH** — `2.1.0 → 2.1.1` | a bug fix / patch |
| any `type!:` or a `BREAKING CHANGE:` body | **MAJOR** — `2.1.0 → 3.0.0` | incompatible change |
| only `docs` / `chore` / `ci` / `test` / `style` | **no release** | nothing user-facing |

The highest applicable bump wins (one `feat` among several `fix`es → minor).

The job then regenerates **`VERSION`**, prepends a section to **`CHANGELOG.md`**,
writes **`RELEASE-NOTES-vX.Y.Z.md`**, commits (`release: vX.Y.Z [skip ci]`),
**tags `vX.Y.Z`**, and creates a **GitLab Release** object (Deploy → Releases)
using those notes as its description — so every release has notes, automatically,
both in-repo and in the GitLab UI.

## So: write Conventional Commits

Your MR's squashed/merge commit subject is what counts. Use:

```
feat(signing): add Windows CA provider
fix(groups): assign a user to multiple groups in one save
feat(api)!: drop the deprecated /v1 endpoints   # ! = breaking -> major
```

Scope (the `(...)`) is optional but nice — it shows up in the changelog.

## One-time setup (required for the auto-release to push)

The job needs to push the release commit + tag back to the protected default
branch, so it needs a token:

1. **Project → Settings → Access Tokens** → create a token with the
   **`write_repository`** scope and **Maintainer** role (e.g. name it
   `release-bot`). Copy the value.
2. **Project → Settings → CI/CD → Variables** → add a **masked, protected**
   variable named **`RELEASE_TOKEN`** with that value.
3. **Project → Settings → Repository → Protected branches** → ensure the token's
   identity is **Allowed to push** to `main` (add the `release-bot` token user,
   or relax "Allowed to push" for maintainers).

Until `RELEASE_TOKEN` is set, the `release` job is a **safe no-op** (it logs and
exits 0 — nothing breaks).

The `[skip ci]` in the release commit stops the push from re-triggering a
pipeline, and the job is idempotent: if the target tag already exists (or the
version is already a `CHANGELOG.md` section) it does nothing.

## Forcing a specific version

Bump `VERSION` by hand in your MR to a value **higher** than the last tag (e.g.
jump to `3.0.0`). `release.sh` honors a manually-set higher `VERSION` and tags
that instead of the computed bump.

## Deploying a release

Tagging doesn't deploy. To roll a tag onto a box: check it out and run
`deploy.sh` there (on the STIG box: `sudo bash deploy.sh`, per the SELinux
exec-under-`/home` note). `deploy.sh` verifies the running app reports the
deployed `VERSION`.
