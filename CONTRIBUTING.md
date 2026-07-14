# Contributing to secretshape

Thanks for considering it. This crate is small on purpose; most of the value is in the
*calibration*, so the bar for changes is about evidence, not volume.

## The two-tier contract (read this first)

- `is_probably_secret` (Tier 1) errs toward **flagging** — false positives are cheap
  (a clipboard forgets a hash).
- `scan`/`Scanner` (Tier 2) errs toward **silence** — false positives are expensive
  (a finding pages a human).

PRs that "unify" the tiers' thresholds, or add a generic high-entropy *rule*, will be
declined regardless of quality. Entropy lives in Tier 1 (and the opt-in
`include_heuristics` pass) only.

## Adding a rule

Every new rule needs all four of:

1. **The pattern**, anchored on a provider prefix or unique structural marker — never a
   bare "long base64" shape.
2. **A severity with a one-line justification** in a comment next to the rule
   (see the existing table in `src/rules.rs` for the register).
3. **≥ 1 true-positive fixture** in `tests/corpus.rs` — a *fake* but format-valid token.
   Use provider-documented examples (`AKIAIOSFODNN7EXAMPLE`) or synthetic strings built
   with `format!`/`repeat`. **Never a real credential**, not even a revoked one — if a
   real-looking token lands in git history, we treat it as leaked.
   Prefer runtime-assembled fixtures (`format!("SK{}", "0123456789abcdef".repeat(2))`)
   over literals: GitHub push protection scans this repo too and — correctly — cannot
   tell a synthetic fixture from a leak, so a format-valid literal blocks the push.
4. **A green run of the false-positive corpus** (`tests/false_positives.rs`).
   Never weaken an anti-corpus entry to make a rule pass — a rule that flags a signed
   CDN URL or a 40-char git SHA is a broken rule, full stop.

Also add the rule's row to the table in the `rules` module docs — a test fails if the
row count drifts from the rule count.

## Rule changes and versioning

- Rule additions/changes can change findings → **minor** version.
- A rule that stopped matching a provider's *current* token format is a bug →
  **patch** release.
- Public API breaks bump 0.x minor pre-1.0.
- MSRV bumps (currently 1.74) are minor-version events, noted in the CHANGELOG.

## Checks that must pass

```bash
cargo test --all-features        # full suite (rules + serde), incl. corpora and doctests
cargo test --no-default-features # the dependency-free tier MUST pass alone
cargo fmt                        # rustfmt.toml: max_width 120, Unix newlines
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
```

`src/heuristics.rs` must never `use regex` or any dependency — it is exactly what
`--no-default-features` ships. No I/O anywhere in the crate: no file walking, no
clipboard, no network verification. Callers own I/O; we judge text.
