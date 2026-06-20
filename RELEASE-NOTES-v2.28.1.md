# CSR Dashboard v2.28.1

_Released 2026-06-20. 1 change since v2.28.0._

## Fixes & improvements

- **ci:** make auto-release resilient to concurrent-merge push races (`d2b8027`)
  Rapid back-to-back MR merges each run a `release` job on main. They raced on the push to the
  protected default branch: the loser got a non-fast-forward rejection and failed the pipeline
  (pipelines 1267-1269). Wrap compute/commit/ tag/push in a 5-attempt loop that re-syncs to
  origin/main and recomputes the version each round. The loser now sees the winner's release
  commit+tag, so release.sh returns "none" and the job no-ops cleanly instead of failing.
  No code or release content changes; tag history is unaffected (later releases through v2.28.0
  already landed).
