//! Redaction (feature `rules`): replace detected secrets with a labeled placeholder,
//! leaving everything else byte-for-byte intact.
//!
//! This is the log-scrubbing tier. The typical placement is a formatting layer or an
//! egress boundary — anywhere text is about to leave your control (a log sink, an LLM
//! prompt, a support ticket):
//!
//! ```
//! // A tracing-style log line about to hit the sink:
//! let line = "refresh failed for token ghp_16C7e42F292c6912E7710c838347Ae178B4a, retrying";
//!
//! assert_eq!(
//!     secretshape::redact(line),
//!     "refresh failed for token [REDACTED:GitHub Token], retrying"
//! );
//!
//! // Clean lines come back borrowed — no allocation on the hot path.
//! assert!(matches!(secretshape::redact("cache warmed in 32ms"), std::borrow::Cow::Borrowed(_)));
//! ```

use crate::rules::Severity;
use crate::scan::{default_scanner, Scanner};
use std::borrow::Cow;
use std::ops::Range;

/// Options for [`redact_with`]. The default masks the whole match.
#[derive(Debug, Clone, Default)]
pub struct RedactOptions {
    keep_edges: usize,
}

impl RedactOptions {
    /// Same as `RedactOptions::default()`: full masking.
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep the first and last `n` characters of each redacted span visible —
    /// `gh[REDACTED:GitHub Token]B4a`-style — so a human can still tell *which*
    /// credential leaked without the log becoming a credential store.
    ///
    /// Edges are only kept when the span is long enough that at least eight characters
    /// stay hidden; short matches are always fully masked (keeping 2+2 of an 8-char
    /// secret is most of the secret).
    pub fn keep_edges(mut self, n: usize) -> Self {
        self.keep_edges = n;
        self
    }
}

/// Replace every finding of the default [`Scanner`] with `[REDACTED:<rule>]`.
///
/// Returns [`Cow::Borrowed`] when nothing matched, so scrubbing clean text is
/// allocation-free. Overlapping findings are merged into one placeholder (labeled with
/// the first, most-severe rule) — the output never contains half a secret.
pub fn redact(text: &str) -> Cow<'_, str> {
    redact_with(text, default_scanner(), &RedactOptions::default())
}

/// [`redact`], but with a caller-configured scanner and options.
///
/// Pair it with [`Scanner::include_heuristics`] when over-masking is cheaper than a
/// leak — the usual trade for LLM-prompt sanitizing:
///
/// ```
/// use secretshape::{redact_with, RedactOptions, Scanner};
///
/// let scanner = Scanner::new().include_heuristics(true);
/// let opts = RedactOptions::new().keep_edges(2);
///
/// let prompt = "summarize: deploy failed, config had AKIAIOSFODNN7EXAMPLE in it";
/// assert_eq!(
///     redact_with(prompt, &scanner, &opts),
///     "summarize: deploy failed, config had AK[REDACTED:AWS Access Key]LE in it"
/// );
/// ```
pub fn redact_with<'t>(text: &'t str, scanner: &Scanner, options: &RedactOptions) -> Cow<'t, str> {
    let findings = scanner.scan(text);
    if findings.is_empty() {
        return Cow::Borrowed(text);
    }

    // Merge overlaps (findings arrive sorted by span start). The label of a merged
    // region is the first finding's rule, breaking exact-tie starts toward higher
    // severity — "which credential" matters more than "also matched a broader pattern".
    let mut merged: Vec<(Range<usize>, &str, Severity)> = Vec::with_capacity(findings.len());
    for finding in &findings {
        match merged.last_mut() {
            Some((span, label, label_severity)) if finding.span.start < span.end => {
                span.end = span.end.max(finding.span.end);
                if span.start == finding.span.start && severity_rank(finding.severity) < severity_rank(*label_severity)
                {
                    *label = finding.rule.as_ref();
                    *label_severity = finding.severity;
                }
            }
            _ => merged.push((finding.span.clone(), finding.rule.as_ref(), finding.severity)),
        }
    }

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (span, label, _) in merged {
        out.push_str(&text[cursor..span.start]);
        mask_into(&mut out, &text[span.clone()], label, options.keep_edges);
        cursor = span.end;
    }
    out.push_str(&text[cursor..]);
    Cow::Owned(out)
}

/// Local severity ordering for label tie-breaking (0 = most severe). Kept private so
/// the crate never publishes an `Ord` for [`Severity`] it would have to defend.
fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
    }
}

fn mask_into(out: &mut String, secret: &str, label: &str, keep_edges: usize) {
    // Keep edges only when at least 8 chars stay hidden; otherwise mask fully.
    let visible_ok = keep_edges > 0 && secret.chars().count() >= keep_edges * 2 + 8;
    if visible_ok {
        let head_end = secret
            .char_indices()
            .nth(keep_edges)
            .map(|(i, _)| i)
            .unwrap_or(secret.len());
        let tail_start = secret
            .char_indices()
            .rev()
            .nth(keep_edges - 1)
            .map(|(i, _)| i)
            .unwrap_or(secret.len());
        out.push_str(&secret[..head_end]);
        out.push_str("[REDACTED:");
        out.push_str(label);
        out.push(']');
        out.push_str(&secret[tail_start..]);
    } else {
        out.push_str("[REDACTED:");
        out.push_str(label);
        out.push(']');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_is_returned_borrowed() {
        let text = "nothing secret here, just a release note for v0.3.1";
        assert!(matches!(redact(text), Cow::Borrowed(_)));
    }

    #[test]
    fn multiple_findings_redact_in_order() {
        let text = "a=AKIAIOSFODNN7EXAMPLE b=ghp_16C7e42F292c6912E7710c838347Ae178B4a done";
        assert_eq!(
            redact(text),
            "a=[REDACTED:AWS Access Key] b=[REDACTED:GitHub Token] done"
        );
    }

    #[test]
    fn overlapping_findings_collapse_to_one_placeholder() {
        // Anthropic key also matches the OpenAI rule; output must not stutter.
        let text = "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEF";
        let redacted = redact(text);
        assert_eq!(redacted.matches("[REDACTED:").count(), 1, "{redacted}");
        assert!(!redacted.contains("api03"), "{redacted}");
    }

    #[test]
    fn keep_edges_shows_head_and_tail_only_when_enough_stays_hidden() {
        let opts = RedactOptions::new().keep_edges(2);
        let scanner = crate::Scanner::new();
        assert_eq!(
            redact_with("AKIAIOSFODNN7EXAMPLE", &scanner, &opts),
            "AK[REDACTED:AWS Access Key]LE"
        );
        // A 9-char match is too short to keep 2+2 visible — masked fully.
        let scanner = scanner
            .with_rule("Tiny Token", crate::Severity::Medium, r"tiny_[0-9]{4}")
            .unwrap();
        assert_eq!(redact_with("tiny_1234", &scanner, &opts), "[REDACTED:Tiny Token]");
    }

    #[test]
    fn redaction_survives_multibyte_neighbours() {
        let text = "🔑 AKIAIOSFODNN7EXAMPLE 🔑";
        assert_eq!(redact(text), "🔑 [REDACTED:AWS Access Key] 🔑");
    }
}
