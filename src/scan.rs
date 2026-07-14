//! The scanning engine (feature `rules`): run the rule set over text, get structured,
//! severity-tagged [`Finding`]s with byte spans.
//!
//! # Overlap policy
//!
//! Two rules matching the same bytes both report. A JWT inside a pasted `Authorization`
//! header is genuinely two findings (the header leaked *and* the token is a bearer
//! credential); deduplicating would force an opinion about which one the caller cares
//! about. [`redact`](crate::redact()) merges overlapping spans itself, so redaction
//! output never stutters.
//!
//! # Why findings don't carry the secret
//!
//! A [`Finding`] holds a byte span, not a copy of the matched text. A detector that
//! hands back every secret it sees is itself a secret-copying machine — it would defeat
//! log scrubbers (the finding object ends up in the log) and make `Debug`/serde output
//! radioactive. Callers who accept that risk can slice: `&text[finding.span.clone()]`.

use crate::rules::{builtin_rules, Rule, Severity};
use regex::Regex;
use std::borrow::Cow;
use std::ops::Range;
use std::sync::OnceLock;

/// One detected secret-shaped region of the input.
///
/// Spans are byte offsets into the *scanned* text and always fall on `char` boundaries,
/// so `&text[finding.span.clone()]` cannot panic. See the module docs for why the
/// matched text itself is not included.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Finding {
    /// Name of the rule that matched (`"GitHub Token"`), or `"high-entropy-token"` for
    /// hits from the opt-in heuristic pass ([`Scanner::include_heuristics`]).
    pub rule: Cow<'static, str>,
    /// How seriously to treat the match — see [`Severity`] for the calibration.
    pub severity: Severity,
    /// Byte range of the match in the scanned text.
    pub span: Range<usize>,
    /// `Some(true)` if the token carries a verifiable checksum and it checks out
    /// (currently: classic GitHub tokens), `Some(false)` if the checksum failed —
    /// advisory, providers can change schemes — and `None` when there is nothing
    /// to verify.
    pub validated: Option<bool>,
}

/// A configurable scanner: the built-in rules, plus/minus caller adjustments.
///
/// ```
/// use secretshape::{Scanner, Severity};
///
/// let scanner = Scanner::new()
///     .without_rule("JWT") // this codebase handles JWTs on purpose
///     .with_rule("Percy Internal Token", Severity::Critical, r"percy_int_[a-f0-9]{32}")
///     .expect("valid pattern");
///
/// let findings = scanner.scan("token = percy_int_0123456789abcdef0123456789abcdef");
/// assert_eq!(findings[0].rule, "Percy Internal Token");
/// ```
#[derive(Debug, Clone)]
pub struct Scanner {
    rules: Vec<Rule>,
    include_heuristics: bool,
    max_input_bytes: usize,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    /// A scanner loaded with the built-in rule set (see the [`rules`](crate::rules)
    /// module docs for the full table), heuristics off, 1 MiB input cap.
    pub fn new() -> Self {
        Scanner {
            rules: builtin_rules().to_vec(),
            include_heuristics: false,
            max_input_bytes: 1 << 20,
        }
    }

    /// Add a custom rule. The name appears verbatim in findings; the pattern should be
    /// anchored on a prefix or structural marker unique to the credential — a bare
    /// "high entropy" pattern belongs in [`include_heuristics`](Self::include_heuristics),
    /// not here, or the rule tier's low-false-positive contract is gone.
    ///
    /// Fails if the pattern is not a valid regex.
    pub fn with_rule(
        mut self,
        name: impl Into<Cow<'static, str>>,
        severity: Severity,
        pattern: &str,
    ) -> Result<Self, InvalidPattern> {
        let regex = Regex::new(pattern).map_err(|source| InvalidPattern(source.to_string()))?;
        self.rules.push(Rule {
            name: name.into(),
            severity,
            regex,
            validator: None,
        });
        Ok(self)
    }

    /// Remove a rule by its exact name (built-in or custom). Unknown names are a no-op —
    /// callers disable rules by policy, and a policy naming a rule this build doesn't
    /// have shouldn't crash the build that *is* running.
    pub fn without_rule(mut self, name: &str) -> Self {
        self.rules.retain(|rule| rule.name != name);
        self
    }

    /// Also flag opaque high-entropy tokens no rule names, as
    /// `Finding { rule: "high-entropy-token", severity: Medium, .. }`.
    ///
    /// **Off by default**, deliberately: this imports the Tier-1 error budget (false
    /// positives are fine) into the tier whose whole contract is precision. Turn it on
    /// for redaction-style uses where over-masking is acceptable; leave it off for
    /// anything that pages a human.
    pub fn include_heuristics(mut self, on: bool) -> Self {
        self.include_heuristics = on;
        self
    }

    /// Cap how many input bytes are scanned (default 1 MiB); the rest is ignored. This
    /// bounds regex work on pathological inputs — a minified bundle pasted as one
    /// "line" — the same guard klappstuhl.me's production scanner runs with. The cut
    /// falls back to the previous `char` boundary, never inside a code point.
    pub fn max_input_bytes(mut self, limit: usize) -> Self {
        self.max_input_bytes = limit;
        self
    }

    /// The active rules, for introspection (dashboards listing what they scan for).
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }

    /// Scan `text`, returning every match of every active rule, sorted by position.
    /// Overlapping findings all report — see the module docs.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let text = clamp_to_boundary(text, self.max_input_bytes);
        let mut findings = Vec::new();
        for rule in &self.rules {
            for m in rule.regex.find_iter(text) {
                findings.push(Finding {
                    rule: rule.name.clone(),
                    severity: rule.severity,
                    span: m.range(),
                    validated: rule.validator.and_then(|verify| verify(m.as_str())),
                });
            }
        }
        if self.include_heuristics {
            self.scan_heuristic_tokens(text, &mut findings);
        }
        findings.sort_by_key(|f| (f.span.start, f.span.end));
        findings
    }

    /// The opt-in entropy pass: whitespace-delimited tokens that pass the Tier-1
    /// entropy shape test and touch no rule finding.
    fn scan_heuristic_tokens(&self, text: &str, findings: &mut Vec<Finding>) {
        let rule_spans: Vec<Range<usize>> = findings.iter().map(|f| f.span.clone()).collect();
        for (start, end) in token_spans(text) {
            let overlaps_rule_hit = rule_spans.iter().any(|span| span.start < end && start < span.end);
            if !overlaps_rule_hit && crate::heuristics::is_entropy_candidate(&text[start..end]) {
                findings.push(Finding {
                    rule: Cow::Borrowed("high-entropy-token"),
                    severity: Severity::Medium,
                    span: start..end,
                    validated: None,
                });
            }
        }
    }
}

/// Scan with the unmodified default [`Scanner`] — the one-liner for the common case.
///
/// ```
/// let findings = secretshape::scan("db = postgres://percy:hunter2@db.internal:5432/percy");
/// assert_eq!(findings.len(), 1);
/// assert_eq!(findings[0].rule, "Database URL with password");
/// ```
pub fn scan(text: &str) -> Vec<Finding> {
    default_scanner().scan(text)
}

/// The shared default scanner ([`scan`] and [`redact`](crate::redact()) both use it) —
/// built once, since callers run these per log line.
pub(crate) fn default_scanner() -> &'static Scanner {
    static SLOT: OnceLock<Scanner> = OnceLock::new();
    SLOT.get_or_init(Scanner::new)
}

/// A custom rule pattern failed to compile. Wraps the regex error message without
/// exposing `regex`'s error type in the public API (that would tie this crate's semver
/// to `regex`'s).
#[derive(Debug)]
pub struct InvalidPattern(String);

impl std::fmt::Display for InvalidPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid rule pattern: {}", self.0)
    }
}

impl std::error::Error for InvalidPattern {}

/// Truncate to at most `limit` bytes without splitting a code point.
fn clamp_to_boundary(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Byte spans of maximal non-whitespace runs.
fn token_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() {
            if let Some(s) = start.take() {
                spans.push((s, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        spans.push((s, text.len()));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_slice_back_to_the_matched_token() {
        let text = "export GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a # deploy";
        let findings = scan(text);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule, "GitHub Token");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(&text[f.span.clone()], "ghp_16C7e42F292c6912E7710c838347Ae178B4a");
    }

    #[test]
    fn overlapping_rules_both_report() {
        // An Anthropic key is also a valid OpenAI-rule match (`sk-` + 40 chars).
        let text = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEF";
        let rules: Vec<_> = scan(text).into_iter().map(|f| f.rule).collect();
        assert!(rules.contains(&Cow::Borrowed("Anthropic API Key")), "{rules:?}");
        assert!(rules.contains(&Cow::Borrowed("OpenAI API Key")), "{rules:?}");
    }

    #[test]
    fn without_rule_removes_and_with_rule_adds() {
        let text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVP";
        assert!(!scan(text).is_empty());
        assert!(Scanner::new().without_rule("JWT").scan(text).is_empty());

        let scanner = Scanner::new()
            .with_rule("ACME Key", Severity::High, r"acme_[0-9]{8}")
            .unwrap();
        let findings = scanner.scan("key: acme_12345678");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "ACME Key");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn invalid_custom_pattern_is_an_error_not_a_panic() {
        assert!(Scanner::new()
            .with_rule("Broken", Severity::Medium, r"(unclosed")
            .is_err());
    }

    #[test]
    fn heuristics_are_off_by_default_and_opt_in() {
        let opaque = "deploy with Xk7pQm2Rv9Ls4Tz8Wn3Yb6Hd please";
        assert!(
            scan(opaque).is_empty(),
            "Tier-2 default must stay silent on bare entropy"
        );

        let findings = Scanner::new().include_heuristics(true).scan(opaque);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "high-entropy-token");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(&opaque[findings[0].span.clone()], "Xk7pQm2Rv9Ls4Tz8Wn3Yb6Hd");
    }

    #[test]
    fn heuristic_pass_does_not_double_report_rule_hits() {
        let text = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
        let findings = Scanner::new().include_heuristics(true).scan(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "GitHub Token");
    }

    #[test]
    fn max_input_bytes_truncates_on_char_boundaries() {
        // 2-byte chars; an odd byte cap must fall back, not panic.
        let text = "ééééé ghp_16C7e42F292c6912E7710c838347Ae178B4a";
        let findings = Scanner::new().max_input_bytes(7).scan(text);
        assert!(findings.is_empty());
        // Large enough cap sees the token again.
        let findings = Scanner::new().max_input_bytes(1024).scan(text);
        assert_eq!(findings.len(), 1);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn finding_serde_round_trip() {
        let finding = &scan("ghp_16C7e42F292c6912E7710c838347Ae178B4a")[0];
        let json = serde_json::to_string(finding).unwrap();
        assert!(json.contains(r#""severity":"critical""#), "{json}");
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, finding);
    }
}
