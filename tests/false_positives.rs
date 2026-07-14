//! The anti-corpus: things people copy, log and commit all day that must produce
//! **zero** Tier-2 findings. This file is the crate's real moat — a rule that fails
//! here is a broken rule, and no entry here may ever be weakened to make a rule pass.
//!
//! Tier 1 (`is_probably_secret`) is *allowed* to flag some of these (its error budget
//! is the opposite one); it is only pinned on the funke "ordinary copies" set at the
//! bottom, the things a clipboard must never forget.

use secretshape::is_probably_secret;

/// Everyday text that the rule tier must stay silent on.
#[cfg(feature = "rules")]
fn anti_corpus() -> Vec<String> {
    let s = |text: &str| text.to_string();
    vec![
        // URLs — including the hard case: long signed CDN URLs.
        s("https://github.com/klappstuhlpy/funke/releases/tag/v0.3.1"),
        s("https://crates.io/crates/secretshape"),
        s("https://d1111abcdef8.cloudfront.net/media/trailer.mp4?Expires=1767139200&Signature=kNQ3fyzoQZQyT3bNVEdSGXxbYnJhZGxleQ__&Key-Pair-Id=APKAEXAMPLEEXAMPLE"),
        format!(
            "https://storage.googleapis.com/bucket/file.bin?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature={}",
            "9a2b".repeat(16)
        ),
        s("https://api.example.com:8443/v1/users?page=2&per_page=50"),
        s("https://discord.com/channels/1095205023137786580/1095205023137786581"),
        s("https://discord.gg/rustlang"),
        s("redis://localhost:6379/0"),
        s("postgres://localhost/percy"),
        // Paths, Windows and Unix.
        s(r"C:\Users\bened\Documents\Coding\funke\README.md"),
        s("/usr/local/bin/cargo"),
        s("~/.config/nvim/init.lua"),
        // Hashes: git SHA-1 (40), SHA-256 (64), a Cargo.lock checksum line.
        s("3b18e512dba79e4c8300dd08aeb37f8e728b8dad"),
        s("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        s(r#"checksum = "9f14dec6c4d3f174a9a5a72abd348c9f34a5a8a8fe7ba1e5d5c96dad3c8b0e2f""#),
        // UUIDs (bare — the Heroku rule requires context, and must keep requiring it).
        s("550e8400-e29b-41d4-a716-446655440000"),
        // Emails, versions.
        s("bigbenwashere@gmail.com"),
        s("1.2.3-beta.1+build.5"),
        s("v0.3.1"),
        // Command lines.
        s("cargo clippy --workspace --all-targets -- -D warnings"),
        s("npm install --save-dev typescript@5.4.2"),
        s("docker run -e POSTGRES_PASSWORD=postgres postgres:16"),
        // Prose, English and German.
        s("The quick brown fox jumps over the lazy dog, twice on Sundays."),
        s("Die Änderung wurde übernommen — Grüße aus Köln an das ganze Team."),
        s("the cache key-value store restarted cleanly"),
        // Hex colors.
        s("#1a2b3c, #FF8800, #d0d0d0"),
        // Base64 test-fixture data, incl. lorem base64 near the entropy threshold.
        s("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpIGVsaXQ="),
        s("bG9yZW0gaXBzdW0="),
        // Data URIs: verdict — no Tier-2 finding. (Tier 1 may drop them; that's its
        // documented budget, and an inlined asset is rarely the copy you miss.)
        s("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="),
        // Colon-delimited non-credentials that must not read as pgpass lines.
        s("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        s("00:1B:44:11:3A:B7"),
        s("2026-07-14T12:30:45+02:00"),
        // YAML that name-drops a sensitive key without a value.
        s("client-key-data: <redacted>"),
    ]
}

#[cfg(feature = "rules")]
#[test]
fn the_anti_corpus_yields_zero_findings() {
    for input in anti_corpus() {
        let findings = secretshape::scan(&input);
        assert!(findings.is_empty(), "false positive on {input:?}: {findings:?}");
    }
}

/// Tier-1 pin: the funke "ordinary copies" set — the strings a clipboard history must
/// never forget — stays kept even though Tier 1 is allowed to over-flag elsewhere.
#[test]
fn tier1_keeps_ordinary_copies() {
    for kept in [
        "https://github.com/klappstuhlpy/funke/releases/tag/v0.3.1",
        r"C:\Users\bened\Documents\Coding\funke\README.md",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "bigbenwashere@gmail.com",
        "Guten Morgen, wie geht es dir?",
        "supercalifragilistic",
        "42",
        "",
    ] {
        assert!(!is_probably_secret(kept), "tier 1 dropped an ordinary copy: {kept:?}");
    }
}

// ── Panic safety ("property-ish"): no input may panic, and every span must slice. ──

fn pathological_inputs() -> Vec<String> {
    vec![
        String::new(),
        "\0".repeat(1000),
        // A megabyte-long single line (the minified-bundle case).
        "ab3!".repeat(300_000),
        // A megabyte of one repeated char (entropy counters must not overflow).
        "a".repeat(1 << 20),
        // Multibyte chars everywhere, including right around the 1 MiB truncation point.
        "é🔑ß".repeat(150_000),
        // A secret placed just before the truncation boundary of multibyte filler.
        format!("{}ghp_16C7e42F292c6912E7710c838347Ae178B4a", "ä".repeat(524_000)),
        // Whitespace-only, and newline-heavy input for the (?m) rules.
        " \t\n\r".repeat(1000),
        format!("{}\n", "x:1:y:z:aaaa\n".repeat(500)),
    ]
}

#[test]
fn tier1_never_panics() {
    for input in pathological_inputs() {
        let _ = is_probably_secret(&input);
    }
}

#[cfg(feature = "rules")]
#[test]
fn tier2_never_panics_and_spans_always_slice() {
    use secretshape::Scanner;
    let scanner = Scanner::new().include_heuristics(true);
    for input in pathological_inputs() {
        for finding in scanner.scan(&input) {
            let _ = &input[finding.span.clone()]; // must not panic
        }
        let _ = secretshape::redact(&input);
    }
    // Truncation limits that land inside code points must fall back, not panic.
    for limit in 0..8 {
        let text = "é🔑ß ghp_16C7e42F292c6912E7710c838347Ae178B4a";
        let _ = Scanner::new().max_input_bytes(limit).scan(text);
    }
}
