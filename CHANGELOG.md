# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 policy: API breaks bump the minor version (0.x); rule changes (which can change
findings) are also minor; provider-format fixes are patches.

## [Unreleased]

## [0.1.0] - 2026-07-14

Initial release, merging two production implementations by the same author: the
clipboard-history guard from [funke](https://github.com/klappstuhlpy/funke) and the
filesystem secret scanner from klappstuhl.me's admin platform.

### Added

- **Tier 1** (dependency-free, always available): `is_probably_secret(&str) -> bool` —
  vendor prefixes, JWT structure, PEM armor, character-class + Shannon-entropy
  heuristics. Errs toward flagging; ported behavior-identical from funke.
- **Tier 2** (feature `rules`, default): 50 severity-tagged provider rules
  (AWS, GCP, Azure, GitHub, GitLab, Stripe, Slack, Discord, OpenAI, Anthropic,
  private-key blocks, DSNs-with-password, and ~35 more). Tuned for a low
  false-positive rate; every rule is anchored on a provider prefix or structural
  marker — no generic entropy rules.
- `scan(&str) -> Vec<Finding>` and the `Scanner` builder: `with_rule`,
  `without_rule`, `include_heuristics` (opt-in entropy pass, off by default),
  `max_input_bytes` (1 MiB default truncation guard).
- `Finding { rule, severity, span, validated }` — byte spans, never a copy of the
  secret; `validated` verifies the CRC32 checksum embedded in classic GitHub tokens.
- `redact` / `redact_with` + `RedactOptions::keep_edges` — replace findings with
  `[REDACTED:<rule>]`, borrow-through when clean, overlap-merged output.
- Feature `serde`: `Serialize`/`Deserialize` on `Finding` and `Severity`
  (lowercase severity strings: `critical` / `high` / `medium`).
- True-positive corpus (one fixture per rule, enforced by test) and the
  false-positive anti-corpus (signed CDN URLs, git SHAs, UUIDs, paths, prose,
  MAC/IPv6 addresses, data URIs); panic-safety tests for pathological inputs.
- MSRV 1.74. `#![forbid(unsafe_code)]`.
