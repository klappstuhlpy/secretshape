<div align="center">

# secretshape

[![CI](https://github.com/klappstuhlpy/secretshape/actions/workflows/ci.yml/badge.svg)](https://github.com/klappstuhlpy/secretshape/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/secretshape.svg)](https://crates.io/crates/secretshape)
[![docs.rs](https://img.shields.io/docsrs/secretshape)](https://docs.rs/secretshape)
![MSRV](https://img.shields.io/badge/MSRV-1.74-blue)

</div>

**Does this string look like a secret?**

A small Rust library for detecting credential-*shaped* text: vendor token prefixes
(`ghp_`, `sk-ant-`, `AKIA…`), structural formats (JWTs, PEM blocks, connection
strings with embedded passwords) and, for the opaque rest, character-class +
Shannon-entropy heuristics.

Built for the places existing secret scanners don't reach: **clipboard managers,
log scrubbers, LLM-prompt sanitizers, paste guards, CI hooks** — anywhere the
question is *"should this text be kept / shown / sent?"*, answered in
microseconds, not *"is this repository clean?"*.

## Two tiers, opposite error budgets

| Tier | Cost | Deps | Errs toward | Use |
|------|------|------|-------------|-----|
| `is_probably_secret(&str) -> bool` | ~µs | none | **flagging** — a kept API key is worse than a forgotten hash | drop/keep decisions (clipboards, prompts) |
| `scan(&str) -> Vec<Finding>` | one regex pass | `regex` (feature `rules`) | **silence** — a finding pages a human | reporting, redaction, dashboards |

The tiers are calibrated against each other on purpose. The bool tier may
false-positive freely; the rule tier may not — its 50 rules all anchor on a
provider prefix or unique structural marker, and generic high-entropy matching is
only available as an explicit opt-in (`Scanner::include_heuristics`).

## Usage

### Clipboard guard (the funke use case)

```rust
// Dependency-free: works with `default-features = false`.
fn on_clipboard_copy(text: &str) {
    if secretshape::is_probably_secret(text) {
        return; // never record it
    }
    // ...store in history...
}
```

### Log scrubbing (a `tracing`-style formatting layer)

```rust
let line = "refresh failed for token ghp_16C7e42F292c6912E7710c838347Ae178B4a, retrying";
assert_eq!(
    secretshape::redact(line),
    "refresh failed for token [REDACTED:GitHub Token], retrying"
);
// Clean lines come back as Cow::Borrowed — no allocation on the hot path.
```

### Structured findings (dashboards, CI)

```rust
use secretshape::{Scanner, Severity};

let scanner = Scanner::new()
    .without_rule("JWT") // this service passes JWTs around on purpose
    .with_rule("ACME Internal Token", Severity::Critical, r"acme_int_[a-f0-9]{32}")
    .unwrap();

for finding in scanner.scan(line) {
    // Findings carry byte spans, never a copy of the secret —
    // slice `&line[finding.span]` yourself if you accept the risk.
    alert(finding.rule, finding.severity.as_str(), finding.span);
}
```

### LLM-prompt sanitizing (over-masking is cheaper than a leak)

```rust
use secretshape::{redact_with, RedactOptions, Scanner};

let scanner = Scanner::new().include_heuristics(true); // + opaque high-entropy tokens
let opts = RedactOptions::new().keep_edges(2);         // AK[REDACTED:AWS Access Key]LE
let safe_prompt = redact_with(user_text, &scanner, &opts);
```

### Axum middleware sketch (scrub response bodies at the egress boundary)

```rust,ignore
async fn scrub_errors(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    if response.status().is_server_error() {
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 64 * 1024).await.unwrap_or_default();
        let scrubbed = secretshape::redact(&String::from_utf8_lossy(&bytes)).into_owned();
        return Response::from_parts(parts, Body::from(scrubbed));
    }
    response
}
```

## What this cannot catch — honestly

- **Short human passwords.** `Sommer2024!` is a word with a number on the end; shape
  analysis cannot see it. Keep managed passwords out upstream (clipboard exclusion
  markers, vault hygiene).
- **Novel token formats** with no prefix and no structure, until a rule lands.
- **Secrets split across lines** — both tiers judge the text they are given.
- **Truth.** This crate judges shape, never validity: no network verification, ever.
  (The one exception in spirit: classic GitHub tokens embed a CRC32 checksum, which is
  verified *offline* into `Finding::validated`.)

## Why not gitleaks / ripsecrets / trufflehog / secrecy?

Different jobs:

| Tool | What it is | What it answers |
|------|-----------|-----------------|
| [gitleaks](https://github.com/gitleaks/gitleaks) | CLI, Go | "is this repo/git-history clean?" |
| [ripsecrets](https://github.com/sirwart/ripsecrets) | CLI, Rust | "am I about to commit a secret?" |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | CLI, Go | "is this leaked credential *live*?" (network verification) |
| [secrecy](https://crates.io/crates/secrecy) | Rust library | "how do I *hold* a secret I already know about?" |
| **secretshape** | Rust library | **"does this arbitrary string *look like* a secret?"** |

No file walking, no git, no network, no CLI — callers own I/O; this crate judges text.
(Some rule patterns are adapted from gitleaks' MIT-licensed rule set, with attribution
in the source.)

## Features & MSRV

| Feature | Default | Brings |
|---------|---------|--------|
| `rules` | ✔ | `scan`, `Scanner`, `Finding`, `Severity`, `redact` (dep: `regex`) |
| `serde` | ✘ | `Serialize`/`Deserialize` on `Finding`/`Severity` (dep: `serde`) |

`default-features = false` leaves a dependency-free crate exposing just
`is_probably_secret` — small enough for the hot path of a clipboard hook.

MSRV: **Rust 1.74** (checked in CI; bumping it is a minor-version event).

## Performance (measured, not assumed)

Criterion, Windows 11 dev box (2026-07), `cargo bench --bench detect`:

| Benchmark | Time |
|-----------|------|
| `is_probably_secret` — vendor token (prefix hit) | ~4 ns |
| `is_probably_secret` — short prose / 1 KiB paste | ~57–60 ns |
| `is_probably_secret` — URL | ~84 ns |
| `is_probably_secret` — opaque token (entropy path, worst case) | ~273 ns |
| `scan` — clean 8 KiB line, all 50 rules | ~19.4 µs |
| `scan` — dirty 8 KiB line (2 secrets) | ~20.4 µs |
| `scan` — clean 8 KiB line, `include_heuristics(true)` | ~43.9 µs |
| `redact` — clean line (borrow-through) | ~465 ns |
| `redact` — dirty line | ~1.5 µs |

Targets were Tier 1 < 1 µs on typical clips and Tier 2 < 50 µs per 8 KiB line — both
met with margin, which is why there is no `RegexSet` prefilter: the added complexity
wasn't buying anything at these numbers.

## License

MIT OR Apache-2.0, at your option.
