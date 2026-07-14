//! Tier 1 — "does this look like a secret?", answered without a single dependency.
//!
//! This tier exists for the caller who cannot afford a regex engine or a false *negative*:
//! a clipboard manager deciding keep-or-drop, a prompt sanitizer deciding send-or-strip.
//! It judges *shape* — vendor prefixes, JWT structure, PEM armor, and for the opaque rest
//! a character-class + Shannon-entropy test.
//!
//! It is a heuristic and it is honest about that: it will miss secrets (a short human
//! password is indistinguishable from a word) and it will occasionally drop something
//! harmless (a long random-looking id). It errs toward dropping, because a clipboard
//! history that quietly keeps an API key is worse than one that quietly forgets a hash.
//! The opposite error budget — precision over recall — lives in the [`rules`](crate::rules)
//! tier.

/// Vendor prefixes that are never anything but a credential, each with a human-readable
/// label so the rule tier can reuse this table as its single source of truth for naming.
///
/// Entries here need no suffix format: the prefix alone is damning. Prefixes that are too
/// generic to match on sight (Mailgun's `key-`, crates.io's `cio`) stay out — they only
/// exist as full-format regexes in the rule tier, where a false positive costs more than
/// a shrug.
pub(crate) const TOKEN_PREFIXES: &[(&str, &str)] = &[
    ("ghp_", "GitHub personal access token"),
    ("gho_", "GitHub OAuth"),
    ("ghu_", "GitHub user-to-server"),
    ("ghs_", "GitHub server-to-server"),
    ("ghr_", "GitHub refresh"),
    ("github_pat_", "GitHub fine-grained PAT"),
    ("glpat-", "GitLab"),
    ("sk-", "OpenAI & friends"),
    ("sk_live_", "Stripe secret"),
    ("sk_test_", "Stripe test secret"),
    ("rk_live_", "Stripe restricted"),
    (
        "pk_live_",
        "Stripe publishable (not secret, but nobody wants it in history)",
    ),
    ("xox", "Slack (xoxb-, xoxp-, xoxa-, …)"),
    ("AKIA", "AWS access key id"),
    ("ASIA", "AWS temporary access key id"),
    ("AIza", "Google API key"),
    ("ya29.", "Google OAuth access token"),
    ("npm_", "npm automation token"),
    ("dop_v1_", "DigitalOcean"),
    ("shpat_", "Shopify private app token"),
    ("shpss_", "Shopify shared secret"),
    ("SG.", "SendGrid"),
    ("hf_", "Hugging Face"),
    ("gsk_", "Groq"),
    ("sk-ant-", "Anthropic"),
    ("dckr_pat_", "Docker Hub personal access token"),
    ("nfp_", "Netlify personal access token"),
    ("fo1_", "Fly.io"),
    ("hvs.", "HashiCorp Vault service token"),
    ("pypi-", "PyPI API token"),
    ("rubygems_", "RubyGems API key"),
    ("sq0atp-", "Square access token"),
    ("sq0csp-", "Square OAuth secret"),
    ("AGE-SECRET-KEY-", "age encryption identity"),
    ("Bearer ", "an Authorization header, pasted whole"),
    ("-----BEGIN", "PEM: private keys, certificates"),
];

/// The shortest opaque token we will judge by shape alone. Below this, false positives
/// (commit hashes are 40 chars, but so is nothing else you copy) outweigh the catch.
const MIN_ENTROPY_LEN: usize = 20;
/// Shannon entropy per character. English prose sits near 2–3; base64/hex key material
/// sits above 4. The bar is deliberately above prose and below the theoretical max.
const MIN_ENTROPY_BITS: f64 = 3.2;

/// Is this text shaped like a credential? See the module docs for what that buys —
/// and, as importantly, what it cannot: a short human-chosen password (`Sommer2024!`)
/// is a word with a number on the end, and nothing about its shape gives it away.
pub fn is_probably_secret(text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return false;
    }
    // A PEM block is multi-line; check it before the single-token gate below.
    if text.starts_with("-----BEGIN") {
        return true;
    }
    // Prose is not a secret, and anything with a space in it is prose — except the
    // vendor prefixes, which are matched first.
    if TOKEN_PREFIXES.iter().any(|(prefix, _)| text.starts_with(prefix)) {
        return true;
    }
    if text.contains(char::is_whitespace) {
        return false;
    }
    // Things that *look* random but are yours to keep: links and paths. A URL is high
    // entropy and full of symbols; forgetting the one you just copied would be maddening.
    if text.contains("://") || text.starts_with("www.") || text.contains('\\') || text.starts_with('/') {
        return false;
    }
    if is_jwt(text) {
        return true;
    }

    text.chars().count() >= MIN_ENTROPY_LEN && character_classes(text) >= 3 && entropy_bits(text) >= MIN_ENTROPY_BITS
}

/// The entropy-shape test alone, for a single whitespace-free token — what the rule tier's
/// opt-in `include_heuristics` mode uses to flag opaque tokens no provider rule names.
/// Same exclusions as [`is_probably_secret`], minus the prefix table (the rule tier
/// already covers every prefix with a full-format regex or consciously leaves it out).
#[cfg(feature = "rules")]
pub(crate) fn is_entropy_candidate(token: &str) -> bool {
    if token.contains("://") || token.starts_with("www.") || token.contains('\\') || token.starts_with('/') {
        return false;
    }
    token.chars().count() >= MIN_ENTROPY_LEN && character_classes(token) >= 3 && entropy_bits(token) >= MIN_ENTROPY_BITS
}

/// `header.payload.signature`, all base64url — a JSON Web Token, i.e. a bearer credential.
fn is_jwt(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 3
        && parts[0].starts_with("ey")
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
        })
}

/// How many of {lowercase, uppercase, digit, symbol} appear. A single class is a word,
/// a number, or a hash — not the mixed alphabet key material tends to have.
fn character_classes(text: &str) -> u8 {
    let (mut lower, mut upper, mut digit, mut symbol) = (false, false, false, false);
    for c in text.chars() {
        match c {
            c if c.is_lowercase() => lower = true,
            c if c.is_uppercase() => upper = true,
            c if c.is_ascii_digit() => digit = true,
            _ => symbol = true,
        }
    }
    u8::from(lower) + u8::from(upper) + u8::from(digit) + u8::from(symbol)
}

/// Shannon entropy of the character distribution, in bits per character.
///
/// ASCII counts live in a flat array — this runs on every clipboard copy, and a
/// `HashMap` allocation per call is silly for text that is almost always ASCII.
/// Non-ASCII falls back to a map keyed by `char`. Counts are `u32`, not `u16`:
/// a pathological megabyte of one repeated character must saturate the math,
/// not overflow it.
fn entropy_bits(text: &str) -> f64 {
    let mut ascii = [0u32; 128];
    let mut other: Option<std::collections::HashMap<char, u32>> = None;
    let mut total = 0u64;
    for c in text.chars() {
        let code = c as u32;
        if code < 128 {
            ascii[code as usize] += 1;
        } else {
            *other.get_or_insert_with(Default::default).entry(c).or_insert(0) += 1;
        }
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    let term = |count: u32| -> f64 {
        if count == 0 {
            return 0.0;
        }
        let p = f64::from(count) / total;
        -p * p.log2()
    };
    ascii.iter().copied().map(term).sum::<f64>()
        + other
            .iter()
            .flat_map(|map| map.values().copied())
            .map(term)
            .sum::<f64>()
}

// The four test blocks below are ported verbatim from funke's `secret.rs` — they encode
// the product decisions (what must be caught, what must be kept, the documented blind
// spot) and double as the behavioral pin for funke's migration onto this crate.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_tokens_and_keys_are_caught_outright() {
        assert!(is_probably_secret("ghp_16C7e42F292c6912E7710c838347Ae178B4a"));
        assert!(is_probably_secret("sk-ant-api03-abcDEF123456"));
        assert!(is_probably_secret("AKIAIOSFODNN7EXAMPLE"));
        assert!(is_probably_secret("xoxb-1234-5678-abcdefghijklmnop"));
        assert!(is_probably_secret(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r\n-----END"
        ));
        assert!(is_probably_secret(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ));
    }

    #[test]
    fn random_looking_tokens_are_caught_by_shape() {
        assert!(is_probably_secret("Xk7pQm2Rv9Ls4Tz8Wn3Yb6Hd"));
        assert!(is_probably_secret("aG9sZG9udGhpc2lzYmFzZTY0ISE=Zm9v"));
    }

    /// The failure that would make the feature worse than useless: forgetting the things
    /// people actually copy all day.
    #[test]
    fn ordinary_copies_are_kept() {
        assert!(!is_probably_secret(
            "https://github.com/klappstuhlpy/funke/releases/tag/v0.3.1"
        ));
        assert!(!is_probably_secret(r"C:\Users\bened\Documents\Coding\funke\README.md"));
        assert!(!is_probably_secret(
            "cargo clippy --workspace --all-targets -- -D warnings"
        ));
        assert!(!is_probably_secret("bigbenwashere@gmail.com"));
        assert!(!is_probably_secret("Guten Morgen, wie geht es dir?"));
        assert!(!is_probably_secret("supercalifragilistic"));
        assert!(!is_probably_secret("42"));
        assert!(!is_probably_secret(""));
    }

    /// Documented blind spot: a short human-chosen password is a word with a number on
    /// the end, and nothing about its shape gives it away. Exclusion markers (or whatever
    /// the caller's first line of defence is), not this function, are what keep managed
    /// passwords out of a history.
    #[test]
    fn a_short_human_password_is_not_detectable_by_shape() {
        assert!(!is_probably_secret("Sommer2024!"));
    }

    /// The entropy fast path must agree with the naive definition on non-ASCII input too.
    #[test]
    fn entropy_handles_non_ascii() {
        // Four distinct chars, uniform distribution → exactly 2 bits/char.
        assert!((entropy_bits("äöüß") - 2.0).abs() < 1e-9);
        // One repeated char → zero entropy, regardless of how long it runs.
        assert_eq!(entropy_bits(&"é".repeat(100_000)), 0.0);
        assert_eq!(entropy_bits(""), 0.0);
    }
}
