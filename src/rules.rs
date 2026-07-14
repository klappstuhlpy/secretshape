//! Tier 2 — severity-tagged provider rules (feature `rules`).
//!
//! Each rule is a (name, severity, regex) triple compiled once on first use. Patterns are
//! tuned for *low false-positive rate over high coverage* — we'd rather miss a generic
//! API key than page a human over a base64-encoded test fixture. Generic high-entropy
//! detection is deliberately omitted for that reason; every rule below anchors on a
//! provider-specific prefix or a unique structural marker. (The opposite trade-off lives
//! in [`is_probably_secret`](crate::is_probably_secret), where a false positive costs a
//! forgotten clipboard entry, not an alert.)
//!
//! Several of the newer patterns are ported from gitleaks' rule set
//! (<https://github.com/gitleaks/gitleaks>, MIT license) and adapted; the rest come from
//! provider documentation or klappstuhl.me's production scanner.
//!
//! # The rules
//!
//! Example shapes are abbreviated; `·` marks where the random payload continues.
//!
//! | Rule | Severity | Example shape |
//! |------|----------|---------------|
//! | AWS Access Key | critical | `AKIAIOSFODNN7EXAMPLE` |
//! | AWS Secret Key | critical | `aws_secret_access_key = "wJalrXUtnFEMI·"` |
//! | Google API Key | critical | `AIzaSyA·` (39 chars) |
//! | Google OAuth Access Token | critical | `ya29.a0Af·` |
//! | GCP Service Account | critical | `"type": "service_account"` |
//! | Firebase FCM Server Key | critical | `AAAAxxxxxxx:APA91b·` |
//! | GitHub Token | critical | `ghp_·` / `gho_·` / `ghu_·` / `ghs_·` / `ghr_·` (40 chars) |
//! | GitHub Fine-Grained PAT | critical | `github_pat_·` (93 chars) |
//! | GitLab PAT | critical | `glpat-·` (20+ chars) |
//! | npm Token | critical | `npm_·` (40 chars) |
//! | Docker Hub PAT | critical | `dckr_pat_·` |
//! | PyPI API Token | critical | `pypi-AgEIcHlwaS5vcmc·` |
//! | crates.io Token | high | `cio·` (32+ chars) |
//! | RubyGems API Key | critical | `rubygems_·` (48 hex) |
//! | Stripe Live Secret | critical | `sk_live_·` (24+ chars) |
//! | Stripe Test Secret | high | `sk_test_·` (24+ chars) |
//! | Square Access Token | critical | `sq0atp-·` (22 chars) |
//! | Square OAuth Secret | critical | `sq0csp-·` (43 chars) |
//! | Braintree Access Token | critical | `access_token$production$·$·` |
//! | Shopify Token | critical | `shpat_·` / `shpss_·` / `shpca_·` / `shppa_·` (32 hex) |
//! | Slack Token | critical | `xoxb-·` / `xoxp-·` / `xoxa-·` / … |
//! | Slack Webhook | high | `https://hooks.slack.com/services/T·/B·/·` |
//! | Discord Bot Token | critical | `M·.G·.·` (base64 triplet) |
//! | Discord Webhook URL | high | `https://discord.com/api/webhooks/·/·` |
//! | Telegram Bot Token | critical | `110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw` |
//! | OpenAI API Key | critical | `sk-·` / `sk-proj-·` (40+ chars) |
//! | Anthropic API Key | critical | `sk-ant-api03-·` |
//! | Hugging Face Token | critical | `hf_·` (37 chars) |
//! | Groq API Key | critical | `gsk_·` (56 chars) |
//! | Azure Storage Account Key | critical | `AccountKey=·==` (88 base64) |
//! | Azure SAS Token | high | `sv=2024-11-04&…&sig=·` |
//! | Azure AD Client Secret | high | `xxx8Q~·` (40 chars) |
//! | DigitalOcean Token | critical | `dop_v1_·` (64 hex) |
//! | Heroku API Key | high | `HEROKU_API_KEY=<uuid>` (context-anchored) |
//! | Fly.io Token | critical | `fo1_·` |
//! | Vercel Token | high | `VERCEL_TOKEN=·` (context-anchored, 24 chars) |
//! | Netlify PAT | critical | `nfp_·` |
//! | Cloudflare API Token | high | `CLOUDFLARE_API_TOKEN=·` (context-anchored, 40 chars) |
//! | Twilio API Key | critical | `SK·` (32 hex) |
//! | SendGrid API Key | critical | `SG.·.·` |
//! | Mailgun API Key | high | `key-·` (32 hex) |
//! | Mailchimp API Key | critical | `·-us6` (32 hex + datacenter) |
//! | HashiCorp Vault Token | critical | `hvs.·` / `hvb.·` |
//! | Age Secret Key | critical | `AGE-SECRET-KEY-1·` |
//! | Private Key Block | critical | `-----BEGIN … PRIVATE KEY-----` |
//! | JWT | medium | `eyJ·.eyJ·.·` |
//! | Database URL with password | high | `postgres://user:pass@host` |
//! | HTTP Basic Auth Header | high | `Authorization: Basic dXNlcjpodW50ZXIy` |
//! | pgpass Line | medium | `host:5432:db:user:password` |
//! | Kubernetes Client Key | medium | `client-key-data: LS0tLS1·` |

use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

/// How bad it is when a rule fires — chosen per rule for the *finding pipeline*, not for
/// the secret's power. A Critical rule's format is specific enough that a match almost
/// always means a real leak; Medium formats are broad enough to hit documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Severity {
    /// Confirmed live-credential format (AWS keys, GitHub PATs, etc.) —
    /// finding a match here almost always means a real leak.
    Critical,
    /// Likely-secret format (Stripe test keys, context-anchored tokens). Worth
    /// investigating but might be a test fixture.
    High,
    /// Possible secret — broader patterns that catch more but false-positive
    /// occasionally (private-key headers in documentation, for example).
    Medium,
}

impl Severity {
    /// The lowercase dashboard string (`"critical"` / `"high"` / `"medium"`) — the same
    /// values the serde derive produces, kept as a method for `serde`-less callers.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A named, severity-tagged detection pattern — one row of the table in the module docs,
/// or a caller-supplied custom rule (see [`Scanner::with_rule`](crate::Scanner::with_rule)).
///
/// Fields are private so the crate can evolve (a `validator` was already added once);
/// read access goes through the getters. Cloning is cheap — `regex::Regex` is an `Arc`
/// internally.
#[derive(Debug, Clone)]
pub struct Rule {
    pub(crate) name: Cow<'static, str>,
    pub(crate) severity: Severity,
    pub(crate) regex: Regex,
    /// Optional post-match check (e.g. the GitHub token checksum). `None` from the
    /// validator means "this match shape carries no checksum to verify".
    pub(crate) validator: Option<fn(&str) -> Option<bool>>,
}

impl Rule {
    /// The rule's stable, human-readable name (`"GitHub Token"`), also used as the
    /// `rule` field of every [`Finding`](crate::Finding) it produces.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The severity every match of this rule reports.
    pub fn severity(&self) -> Severity {
        self.severity
    }

    /// The regex pattern source, for display and diffing.
    pub fn pattern(&self) -> &str {
        self.regex.as_str()
    }
}

/// The rule table. Kept as plain data so the doc table above, the compiled set, and the
/// tests all draw from one place. Severity rationale rides in the comments — a rule
/// without a reason for its severity is a rule nobody can re-tune later.
#[rustfmt::skip]
const RULES: &[(&str, Severity, &str)] = &[
    // ── Cloud providers ──────────────────────────────────────────────────────────
    // AKIA + 16 uppercase/digits is AWS's documented, fixed format. No other common
    // artifact collides (git SHAs are lowercase hex).
    ("AWS Access Key", Severity::Critical, r"AKIA[0-9A-Z]{16}"),
    // The 40-char secret has no prefix of its own, so anchor on the variable name.
    ("AWS Secret Key", Severity::Critical, r#"(?i)aws[_-]?secret[_-]?access[_-]?key["'\s:=]+[A-Za-z0-9/+=]{40}"#),
    ("Google API Key", Severity::Critical, r"AIza[0-9A-Za-z\-_]{35}"),
    // OAuth access tokens are short-lived, but a pasted one is live *now*.
    ("Google OAuth Access Token", Severity::Critical, r"ya29\.[A-Za-z0-9_.-]{20,}"),
    // The JSON marker of a service-account key file; the private key rule fires too if
    // the whole file is present (overlaps both report — see the scan module docs).
    ("GCP Service Account", Severity::Critical, r#""type"\s*:\s*"service_account""#),
    // Legacy FCM server keys: the `:APA91b` joint is the unique structural marker.
    ("Firebase FCM Server Key", Severity::Critical, r"AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}"),
    // Azure storage account keys are exactly 88 base64 chars ending "==", and in the
    // wild they travel inside a connection string — anchor on the parameter name.
    ("Azure Storage Account Key", Severity::Critical, r"(?i)AccountKey=[A-Za-z0-9+/]{86}=="),
    // A SAS URL is a signed URL, and the false-positive corpus is full of signed URLs —
    // so require the Azure-specific `sv=<api-version>` marker before the `sig=`. SAS
    // links with `sig=` before `sv=` are missed; precision wins that trade (High: the
    // grant may be read-only or expired).
    ("Azure SAS Token", Severity::High, r#"sv=\d{4}-\d{2}-\d{2}[^\s"']*?&sig=[A-Za-z0-9%+/=]{20,}"#),
    // Post-2021 client secrets embed `7Q~`/`8Q~` at offset 3. The character class is
    // broad (base64-with-~ blobs can collide), hence High, not Critical.
    ("Azure AD Client Secret", Severity::High, r"[A-Za-z0-9_~.]{3}[78]Q~[A-Za-z0-9_~.-]{31,34}"),
    ("DigitalOcean Token", Severity::Critical, r"do[opr]_v1_[0-9a-f]{64}"),
    // Heroku keys are bare UUIDs — indistinguishable from any other UUID without the
    // variable-name context, and even with it a match might be an app id. High.
    ("Heroku API Key", Severity::High, r#"(?i)heroku[a-z0-9_ "':=-]{0,20}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#),
    ("Fly.io Token", Severity::Critical, r"fo1_[A-Za-z0-9+/=_-]{40,}"),
    // Vercel tokens are 24 bare lowercase alphanumerics — context-anchored, so a match
    // still needs a human eye (the 24-char word might be a deployment id). High.
    ("Vercel Token", Severity::High, r#"(?i)vercel[a-z0-9_ "':=-]{0,20}\b[a-z0-9]{24}\b"#),
    ("Netlify PAT", Severity::Critical, r"nfp_[A-Za-z0-9_-]{36,}"),
    // Cloudflare tokens are 40 chars with no prefix — same context-anchor treatment.
    ("Cloudflare API Token", Severity::High, r#"(?i)cloudflare[a-z0-9_ "':=-]{0,20}\b[A-Za-z0-9_-]{40}\b"#),
    // ── Source / DevOps ──────────────────────────────────────────────────────────
    // Classic 40-char tokens (ghp_/gho_/ghu_/ghs_/ghr_). Matches carry a CRC32
    // checksum in the last 6 chars; the scanner verifies it into `Finding::validated`.
    ("GitHub Token", Severity::Critical, r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    ("GitHub Fine-Grained PAT", Severity::Critical, r"github_pat_[A-Za-z0-9_]{82}"),
    ("GitLab PAT", Severity::Critical, r"glpat-[A-Za-z0-9\-_]{20,}"),
    ("npm Token", Severity::Critical, r"npm_[A-Za-z0-9]{36}"),
    ("Docker Hub PAT", Severity::Critical, r"dckr_pat_[A-Za-z0-9_-]{27,}"),
    // pypi- followed by the base64 of "pypi.org" — macaroon location, always present.
    ("PyPI API Token", Severity::Critical, r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    // crates.io adopted the `cio` prefix in 2021; the exact payload length is not
    // officially documented, so the length bound is loose and the severity High.
    ("crates.io Token", Severity::High, r"\bcio[A-Za-z0-9]{29,}"),
    ("RubyGems API Key", Severity::Critical, r"rubygems_[0-9a-f]{48}"),
    ("HashiCorp Vault Token", Severity::Critical, r"\bhv[sb]\.[A-Za-z0-9_-]{24,}"),
    // ── Payments / commerce ──────────────────────────────────────────────────────
    ("Stripe Live Secret", Severity::Critical, r"sk_live_[0-9a-zA-Z]{24,}"),
    // Test-mode keys can't move money, but their presence usually means live keys are
    // handled the same careless way. High: investigate, don't page.
    ("Stripe Test Secret", Severity::High, r"sk_test_[0-9a-zA-Z]{24,}"),
    ("Square Access Token", Severity::Critical, r"sq0atp-[A-Za-z0-9_-]{22}"),
    ("Square OAuth Secret", Severity::Critical, r"sq0csp-[A-Za-z0-9_-]{43}"),
    ("Braintree Access Token", Severity::Critical, r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("Shopify Token", Severity::Critical, r"shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}"),
    // ── Chat / messaging ─────────────────────────────────────────────────────────
    ("Slack Token", Severity::Critical, r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    // A webhook is a scoped credential: post-only, one channel. High, not Critical.
    ("Slack Webhook", Severity::High, r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}"),
    ("Discord Bot Token", Severity::Critical, r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,}"),
    ("Discord Webhook URL", Severity::High, r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9\-_]+"),
    // Bot ids are 8–10 digits and the secret part always starts with 'A'; the leading
    // \b keeps the digit run from starting inside a longer number.
    ("Telegram Bot Token", Severity::Critical, r"\b\d{8,10}:A[A-Za-z0-9_-]{34}"),
    // ── AI providers ─────────────────────────────────────────────────────────────
    ("OpenAI API Key", Severity::Critical, r"sk-(?:proj-)?[A-Za-z0-9_-]{40,}"),
    ("Anthropic API Key", Severity::Critical, r"sk-ant-[a-z0-9]+-[A-Za-z0-9_-]{32,}"),
    ("Hugging Face Token", Severity::Critical, r"\bhf_[A-Za-z0-9]{34}\b"),
    ("Groq API Key", Severity::Critical, r"gsk_[A-Za-z0-9]{52}"),
    // ── Email / SMS providers ────────────────────────────────────────────────────
    ("Twilio API Key", Severity::Critical, r"SK[0-9a-fA-F]{32}"),
    ("SendGrid API Key", Severity::Critical, r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    // `key-` is a generic prefix ("cache key-<md5>" is a plausible collision), so High
    // despite the credential being fully privileged.
    ("Mailgun API Key", Severity::High, r"key-[0-9a-f]{32}"),
    // The `-us<n>` datacenter suffix after exactly 32 hex is Mailchimp's marker.
    ("Mailchimp API Key", Severity::Critical, r"\b[0-9a-f]{32}-us\d{1,2}\b"),
    // ── Keys / certificates / tokens ─────────────────────────────────────────────
    ("Age Secret Key", Severity::Critical, r"AGE-SECRET-KEY-1[A-Z0-9]{58}"),
    ("Private Key Block", Severity::Critical, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----"),
    // JWTs are often expired or sample tokens from docs; the structure is unmistakable
    // but the risk needs a human look. Medium.
    ("JWT", Severity::Medium, r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    // ── Generic high-confidence env patterns ─────────────────────────────────────
    // password=plaintext or DATABASE_URL with embedded creds.
    ("Database URL with password", Severity::High, r"(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@[^/\s]+"),
    ("HTTP Basic Auth Header", Severity::High, r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/]{16,}={0,2}"),
    // The five-field colon format of ~/.pgpass. Requires a numeric port and a ≥4-char
    // password so MAC addresses and clock times don't qualify; `*` wildcards in the
    // host field pass, `*` as the port does not (a conscious trade for precision).
    ("pgpass Line", Severity::Medium, r"(?m)^[^:\s]{1,64}:[0-9]{1,5}:[^:\n]{1,64}:[^:\n]{1,64}:[^:\s]{4,}$"),
    // kubeconfig embedded client keys. Base64 of a PEM always starts LS0tLS1, but any
    // value under this YAML key is sensitive; Medium because docs quote the key name.
    ("Kubernetes Client Key", Severity::Medium, r"client-key-data:\s*[A-Za-z0-9+/=]{40,}"),
];

/// Returns the compiled built-in rule set (lazy, one-shot). This is what
/// [`Scanner::new`](crate::Scanner::new) starts from and what
/// [`scan`](crate::scan()) uses unmodified.
pub fn builtin_rules() -> &'static [Rule] {
    static SLOT: OnceLock<Vec<Rule>> = OnceLock::new();
    SLOT.get_or_init(build_rules).as_slice()
}

fn build_rules() -> Vec<Rule> {
    RULES
        .iter()
        .map(|&(name, severity, pattern)| Rule {
            name: Cow::Borrowed(name),
            severity,
            regex: Regex::new(pattern).expect("invalid built-in secret rule regex"),
            validator: match name {
                "GitHub Token" => Some(github_token_checksum),
                _ => None,
            },
        })
        .collect()
}

/// GitHub's classic tokens (`ghp_` + 36 chars) carry a CRC32 of the 30-char payload,
/// base62-encoded into the last 6 chars — documented in GitHub's "behind the scenes of
/// our new authentication token formats" post. `Some(true)` means the checksum verifies
/// (almost certainly a real token, not line noise that happened to match); `Some(false)`
/// means it does not — treat that as *advisory*, since a provider can change the scheme.
/// Matches that aren't exactly prefix + 36 chars return `None` (nothing to verify).
fn github_token_checksum(token: &str) -> Option<bool> {
    let payload = token
        .strip_prefix("gh")?
        .strip_prefix(['p', 'o', 'u', 's', 'r'])?
        .strip_prefix('_')?;
    if payload.len() != 36 || !payload.is_ascii() {
        return None;
    }
    let (random, checksum) = payload.split_at(30);
    Some(base62_6(crc32(random.as_bytes())) == checksum.as_bytes())
}

/// Standard CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), bitwise — 20 lines
/// beat a dependency.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Base62 (0-9A-Za-z), left-padded with '0' to exactly 6 bytes — the encoding GitHub
/// uses for the checksum chars.
fn base62_6(mut n: u32) -> [u8; 6] {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = [b'0'; 6];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(n % 62) as usize];
        n /= 62;
        if n == 0 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_compiles_and_names_are_unique() {
        let rules = builtin_rules();
        assert_eq!(rules.len(), RULES.len());
        let mut names: Vec<&str> = rules.iter().map(Rule::name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), rules.len(), "duplicate rule name");
    }

    /// The doc table at the top of this file must list every rule — this pins the row
    /// count so the table can't silently drift from the RULES slice.
    #[test]
    fn doc_table_lists_every_rule() {
        let source = include_str!("rules.rs");
        let rows = source.lines().filter(|l| l.trim_start().starts_with("//! |")).count();
        // Two header lines (title row + separator row) are not rules.
        assert_eq!(rows - 2, RULES.len(), "rules table in module docs is out of sync");
    }

    #[test]
    fn severity_strings_match_klappstuhl_dashboard_values() {
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Medium.as_str(), "medium");
    }

    /// A self-consistent GitHub token (checksum computed by the same scheme) validates;
    /// tampering with one payload char breaks it.
    #[test]
    fn github_checksum_round_trip() {
        let random = "16C7e42F292c6912E7710c838347Ae"; // 30 chars
        let checksum = base62_6(crc32(random.as_bytes()));
        let token = format!("ghp_{random}{}", std::str::from_utf8(&checksum).unwrap());
        assert_eq!(github_token_checksum(&token), Some(true));

        let tampered = token.replace("16C7", "16C8");
        assert_eq!(github_token_checksum(&tampered), Some(false));

        // A 40-char-payload match has no checksum position to verify.
        assert_eq!(github_token_checksum(&format!("ghp_{}", "a".repeat(40))), None);
    }

    #[test]
    fn crc32_matches_the_ieee_reference_vector() {
        // The canonical check value for CRC-32/ISO-HDLC.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
