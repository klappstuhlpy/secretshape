//! **secretshape** — does this string look like a secret?
//!
//! A small library for detecting credential-*shaped* text: vendor token prefixes
//! (`ghp_`, `sk-ant-`, `AKIA…`), structural formats (JWTs, PEM blocks, DSNs with
//! embedded passwords) and, for the opaque rest, character-class + Shannon-entropy
//! heuristics. Built for clipboard managers, log scrubbers, LLM-prompt sanitizers
//! and CI checks — anywhere the question is "should this text be kept / shown /
//! sent?", not "is this repository clean?".
//!
//! Two tiers:
//! - [`is_probably_secret`] — a dependency-free yes/no fast path that errs toward
//!   *dropping* (a history that quietly keeps an API key is worse than one that
//!   quietly forgets a hash).
//! - `scan` (feature `rules`) — the severity-tagged provider rule engine, tuned
//!   for a low false-positive rate, yielding structured findings.
//!
//! Status: pre-0.1 skeleton. The implementation plan lives in `.claude/PLAN.md`;
//! the reference implementations being merged are funke's clipboard guard and
//! klappstuhl.me's filesystem secret scanner.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Is this text shaped like a credential?
///
/// Placeholder — ported from `funke-clipboard/src/secret.rs` in Phase 1 of the
/// plan. Always returns `false` until then so nothing accidentally ships against
/// the stub.
pub fn is_probably_secret(_text: &str) -> bool {
    unimplemented!("Phase 1 of .claude/PLAN.md: port the funke heuristic tier")
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {}
}
