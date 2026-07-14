//! **secretshape** — does this string look like a secret?
//!
//! A small library for detecting credential-*shaped* text: vendor token prefixes
//! (`ghp_`, `sk-ant-`, `AKIA…`), structural formats (JWTs, PEM blocks, DSNs with
//! embedded passwords) and, for the opaque rest, character-class + Shannon-entropy
//! heuristics. Built for clipboard managers, log scrubbers, LLM-prompt sanitizers
//! and CI checks — anywhere the question is "should this text be kept / shown /
//! sent?", not "is this repository clean?".
//!
//! # Two tiers, opposite error budgets
//!
//! | Tier | Cost | Deps | Errs toward | Use |
//! |------|------|------|-------------|-----|
//! | [`is_probably_secret`] | ~µs | none | **flagging** (a kept API key is worse than a forgotten hash) | drop/keep decisions |
//! | [`scan`] / [`redact`] (feature `rules`) | one regex pass | `regex` | **silence** (a finding pages a human) | reporting, redaction, dashboards |
//!
//! The tiers are calibrated against each other on purpose — don't expect them to
//! agree. The bool says "drop it" far more often than the rule engine says "alert".
//!
//! # Tier 1 — the dependency-free bool
//!
//! ```
//! // A clipboard manager deciding keep-or-drop:
//! assert!(secretshape::is_probably_secret("ghp_16C7e42F292c6912E7710c838347Ae178B4a"));
//! assert!(secretshape::is_probably_secret("Xk7pQm2Rv9Ls4Tz8Wn3Yb6Hd")); // opaque, high entropy
//!
//! // …without forgetting the things people copy all day:
//! assert!(!secretshape::is_probably_secret("https://github.com/klappstuhlpy/funke/releases/tag/v0.3.1"));
//! assert!(!secretshape::is_probably_secret("cargo clippy --workspace -- -D warnings"));
//! ```
//!
//! # Tier 2 — structured findings and redaction (feature `rules`, on by default)
//!
#![cfg_attr(
    feature = "rules",
    doc = r#"```
// A log line on its way to a sink nobody fully controls:
let line = "auth retry with ghp_16C7e42F292c6912E7710c838347Ae178B4a failed twice";

let findings = secretshape::scan(line);
assert_eq!(findings[0].rule, "GitHub Token");
assert_eq!(findings[0].severity, secretshape::Severity::Critical);
// Findings carry byte spans, not the secret itself — slice if you accept the risk.
assert_eq!(&line[findings[0].span.clone()], "ghp_16C7e42F292c6912E7710c838347Ae178B4a");

assert_eq!(
    secretshape::redact(line),
    "auth retry with [REDACTED:GitHub Token] failed twice"
);
```

See [`Scanner`] for custom rules, rule removal, the opt-in entropy pass and input
caps; the full rule table lives in the [`rules`] module docs.
"#
)]
//! # What this cannot catch — honestly
//!
//! - **Short human passwords.** `Sommer2024!` is a word with a number on the end;
//!   nothing about its shape distinguishes it from prose. If you manage passwords,
//!   exclude them upstream (clipboard exclusion markers, vault hygiene) — shape
//!   analysis will not save you.
//! - **Novel token formats.** A provider that launches tomorrow with an unprefixed
//!   32-char token is invisible to the rule tier until a rule lands (the entropy
//!   heuristic may still catch it, at Tier-1 precision).
//! - **Secrets split across lines.** Both tiers judge the text they are given; a key
//!   pasted as two halves is two innocent-looking strings.
//! - **Truth.** This crate judges *shape*, never validity — it does not (and will
//!   not) call provider APIs to verify a match is live.
//!
//! # Features
//!
//! - `rules` *(default)* — the provider rule engine: [`scan`], [`Scanner`],
//!   [`Finding`], [`Severity`], [`redact`]. Pulls in `regex`.
//! - `serde` — `Serialize`/`Deserialize` on [`Finding`] and [`Severity`].
//!
//! With `--no-default-features` the crate is dependency-free and exposes just
//! [`is_probably_secret`] — small enough for the hot path of a clipboard hook.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod heuristics;
#[cfg(feature = "rules")]
mod redact;
#[cfg(feature = "rules")]
pub mod rules;
#[cfg(feature = "rules")]
mod scan;

pub use heuristics::is_probably_secret;
#[cfg(feature = "rules")]
pub use redact::{redact, redact_with, RedactOptions};
#[cfg(feature = "rules")]
pub use rules::{builtin_rules, Rule, Severity};
#[cfg(feature = "rules")]
pub use scan::{scan, Finding, InvalidPattern, Scanner};
