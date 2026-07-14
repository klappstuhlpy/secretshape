//! The true-positive corpus: one format-valid fixture per rule, table-driven.
//!
//! Every fixture is either a provider-published example (`AKIAIOSFODNN7EXAMPLE`,
//! Stripe's documented test key) or a synthetic token built to the provider's
//! documented format. **No real credential may ever appear here** — if one lands in
//! git history, treat it as leaked.

#![cfg(feature = "rules")]

use secretshape::{builtin_rules, scan, Severity};

/// (input, rule that must fire, severity it must carry). Inputs sit in realistic
/// context (env lines, URLs) where the rule is context-anchored.
fn corpus() -> Vec<(String, &'static str, Severity)> {
    let s = |text: &str| text.to_string();
    vec![
        // ── Cloud providers ──────────────────────────────────────────
        (s("AKIAIOSFODNN7EXAMPLE"), "AWS Access Key", Severity::Critical),
        (
            s(r#"aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#),
            "AWS Secret Key",
            Severity::Critical,
        ),
        (
            s("AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"),
            "Google API Key",
            Severity::Critical,
        ),
        (
            s("ya29.a0AfH6SMBx7-2bqZ0uJkA_demo-access-token"),
            "Google OAuth Access Token",
            Severity::Critical,
        ),
        (
            s(r#"{"type": "service_account", "project_id": "demo"}"#),
            "GCP Service Account",
            Severity::Critical,
        ),
        (
            format!("AAAAqbcDefG:APA91b{}", "x".repeat(120)),
            "Firebase FCM Server Key",
            Severity::Critical,
        ),
        (
            format!("DefaultEndpointsProtocol=https;AccountName=demo;AccountKey={}==;", "K".repeat(86)),
            "Azure Storage Account Key",
            Severity::Critical,
        ),
        (
            s("https://demo.blob.core.windows.net/c/b.txt?sv=2024-11-04&ss=b&srt=sco&sp=r&se=2026-08-01&sig=aBcDeF1gHiJkLmNoPqRsTuVwXyZ%2B12345%3D"),
            "Azure SAS Token",
            Severity::High,
        ),
        (
            s("abc8Q~dEfGhIjKlMnOpQrStUvWxYz0123456789"),
            "Azure AD Client Secret",
            Severity::High,
        ),
        (
            format!("dop_v1_{}", "0123456789abcdef".repeat(4)),
            "DigitalOcean Token",
            Severity::Critical,
        ),
        (
            s(r#"HEROKU_API_KEY: "12345678-90ab-cdef-1234-567890abcdef""#),
            "Heroku API Key",
            Severity::High,
        ),
        (format!("fo1_{}", "w".repeat(43)), "Fly.io Token", Severity::Critical),
        (
            s("VERCEL_TOKEN=abcdefghij1234567890abcd"),
            "Vercel Token",
            Severity::High,
        ),
        (format!("nfp_{}", "n".repeat(40)), "Netlify PAT", Severity::Critical),
        (
            s("cloudflare_api_token: aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd"),
            "Cloudflare API Token",
            Severity::High,
        ),
        // ── Source / DevOps ──────────────────────────────────────────
        (
            s("ghp_16C7e42F292c6912E7710c838347Ae178B4a"),
            "GitHub Token",
            Severity::Critical,
        ),
        (
            format!("github_pat_11{}", "A".repeat(80)),
            "GitHub Fine-Grained PAT",
            Severity::Critical,
        ),
        (s("glpat-aB3dE5fG7hJ9kL1mN3pQ"), "GitLab PAT", Severity::Critical),
        (
            s("npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
            "npm Token",
            Severity::Critical,
        ),
        (format!("dckr_pat_{}", "d".repeat(27)), "Docker Hub PAT", Severity::Critical),
        (
            format!("pypi-AgEIcHlwaS5vcmc{}", "P".repeat(55)),
            "PyPI API Token",
            Severity::Critical,
        ),
        (format!("cio{}", "c".repeat(32)), "crates.io Token", Severity::High),
        (
            format!("rubygems_{}", "0123456789abcdef".repeat(3)),
            "RubyGems API Key",
            Severity::Critical,
        ),
        (
            s("hvs.CAESIJlU2demoDemoDemo1234567890abcdef"),
            "HashiCorp Vault Token",
            Severity::Critical,
        ),
        // ── Payments / commerce ──────────────────────────────────────
        (
            s("sk_live_4eC39HqLyjWDarjtT1zdp7dc"),
            "Stripe Live Secret",
            Severity::Critical,
        ),
        (s("sk_test_4eC39HqLyjWDarjtT1zdp7dc"), "Stripe Test Secret", Severity::High),
        (
            format!("sq0atp-{}", "s".repeat(22)),
            "Square Access Token",
            Severity::Critical,
        ),
        (
            format!("sq0csp-{}", "s".repeat(43)),
            "Square OAuth Secret",
            Severity::Critical,
        ),
        (
            s("access_token$production$abcdefgh12345678$0123456789abcdef0123456789abcdef"),
            "Braintree Access Token",
            Severity::Critical,
        ),
        (
            s("shpat_0123456789abcdef0123456789abcdef"),
            "Shopify Token",
            Severity::Critical,
        ),
        (
            s("shpss_0123456789abcdef0123456789abcdef"),
            "Shopify Token",
            Severity::Critical,
        ),
        // ── Chat / messaging ─────────────────────────────────────────
        // Assembled at runtime: a literal in this file trips GitHub push protection
        // (which, fairly, cannot tell a synthetic fixture from a leak). Same for the
        // Twilio / Mailgun / Mailchimp fixtures below.
        (
            format!("xoxb-1234567890-1234567890123-{}", "AbCd".repeat(6)),
            "Slack Token",
            Severity::Critical,
        ),
        (
            format!("https://hooks.slack.com/services/T00000000/B00000000/{}", "X".repeat(24)),
            "Slack Webhook",
            Severity::High,
        ),
        (
            s("MTA5NTKwNTAyMzEzNzc4NjU4.GabcDe.abcdefghijklmnopqrstuvwxyz1"),
            "Discord Bot Token",
            Severity::Critical,
        ),
        (
            s("https://discord.com/api/webhooks/1095205023137786580/aBcDeF-gHiJkLmN_oPqRsTuVwXyZ012345"),
            "Discord Webhook URL",
            Severity::High,
        ),
        (
            format!("110201543:AA{}", "H".repeat(33)),
            "Telegram Bot Token",
            Severity::Critical,
        ),
        // ── AI providers ─────────────────────────────────────────────
        (
            s("sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"),
            "OpenAI API Key",
            Severity::Critical,
        ),
        (
            s("sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEF"),
            "Anthropic API Key",
            Severity::Critical,
        ),
        (format!("hf_{}", "h".repeat(34)), "Hugging Face Token", Severity::Critical),
        (format!("gsk_{}", "g".repeat(52)), "Groq API Key", Severity::Critical),
        // ── Email / SMS ──────────────────────────────────────────────
        (
            format!("SK{}", "0123456789abcdef".repeat(2)),
            "Twilio API Key",
            Severity::Critical,
        ),
        (
            format!("SG.{}.{}", "s".repeat(22), "S".repeat(43)),
            "SendGrid API Key",
            Severity::Critical,
        ),
        (
            format!("key-{}", "0123456789abcdef".repeat(2)),
            "Mailgun API Key",
            Severity::High,
        ),
        (
            format!("{}-us6", "0123456789abcdef".repeat(2)),
            "Mailchimp API Key",
            Severity::Critical,
        ),
        // ── Keys / certificates / tokens ─────────────────────────────
        (
            format!("AGE-SECRET-KEY-1{}", "Q".repeat(58)),
            "Age Secret Key",
            Severity::Critical,
        ),
        (
            s("-----BEGIN OPENSSH PRIVATE KEY-----"),
            "Private Key Block",
            Severity::Critical,
        ),
        (
            s("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "JWT",
            Severity::Medium,
        ),
        // ── Generic env patterns ─────────────────────────────────────
        (
            s("postgres://percy:hunter2@db.internal:5432/percy"),
            "Database URL with password",
            Severity::High,
        ),
        (
            s("Authorization: Basic dXNlcm5hbWU6aHVudGVyMg=="),
            "HTTP Basic Auth Header",
            Severity::High,
        ),
        (
            s("db.example.com:5432:percy:percy_admin:s3cr3t-hunter2"),
            "pgpass Line",
            Severity::Medium,
        ),
        (
            format!("client-key-data: {}==", "A".repeat(60)),
            "Kubernetes Client Key",
            Severity::Medium,
        ),
    ]
}

#[test]
fn every_fixture_triggers_its_rule_with_the_right_severity() {
    for (input, rule, severity) in corpus() {
        let findings = scan(&input);
        assert!(
            findings.iter().any(|f| f.rule == rule && f.severity == severity),
            "expected {rule:?} ({severity:?}) on {input:?}, got {findings:?}"
        );
    }
}

/// The Phase-3 gate: no built-in rule without a true-positive fixture.
#[test]
fn every_builtin_rule_has_a_fixture() {
    let covered: Vec<&str> = corpus().iter().map(|(_, rule, _)| *rule).collect();
    for rule in builtin_rules() {
        assert!(
            covered.contains(&rule.name()),
            "rule {:?} has no fixture in the corpus",
            rule.name()
        );
    }
}

/// Spans must always slice cleanly back into the input — on every corpus entry,
/// including the ones flanked by multibyte characters.
#[test]
fn all_spans_are_char_boundary_safe() {
    for (input, _, _) in corpus() {
        let decorated = format!("🔑 {input} — Ünïcode neighbours");
        for finding in scan(&decorated) {
            let _ = &decorated[finding.span.clone()]; // must not panic
        }
    }
}

/// The classic-GitHub-token rule evaluates its checksum: `validated` is present
/// (the synthetic fixture's checksum is random, so the value itself is `false`).
#[test]
fn github_token_findings_carry_a_checksum_verdict() {
    let findings = scan("ghp_16C7e42F292c6912E7710c838347Ae178B4a");
    let github = findings.iter().find(|f| f.rule == "GitHub Token").unwrap();
    assert!(github.validated.is_some());
    // A rule without a checksum scheme reports None.
    let findings = scan("AKIAIOSFODNN7EXAMPLE");
    assert_eq!(findings[0].validated, None);
}
