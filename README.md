# secretshape

**Does this string look like a secret?**

A small Rust library for detecting credential-*shaped* text: vendor token prefixes
(`ghp_`, `sk-ant-`, `AKIA…`), structural formats (JWTs, PEM blocks, connection
strings with embedded passwords) and, for the opaque rest, character-class +
Shannon-entropy heuristics.

Built for the places existing secret scanners don't reach: **clipboard managers,
log scrubbers, LLM-prompt sanitizers, paste guards, CI hooks** — anywhere the
question is *"should this text be kept / shown / sent?"*, answered in
microseconds, not *"is this repository clean?"*.

```rust
// Fast path: dependency-free yes/no, errs toward "secret".
if secretshape::is_probably_secret(clip) {
    return; // never record it
}

// Rule engine (feature `rules`): structured, severity-tagged findings.
for finding in secretshape::scan(line) {
    println!("{} ({:?}) at {:?}", finding.rule, finding.severity, finding.span);
}
```

## Status

**Pre-0.1 — skeleton only.** The API above is the design target, not yet the
implementation. It merges two battle-tested private implementations: the
clipboard-history guard from [funke](https://github.com/klappstuhlpy/funke) and
the filesystem secret scanner from klappstuhl.me's admin platform.

## Why not gitleaks / ripsecrets / detect-secrets?

Those are repository scanners (and CLIs, and not Rust libraries). `secretshape`
is a library with a two-tier design:

| Tier | Cost | Deps | Use |
|------|------|------|-----|
| `is_probably_secret(&str) -> bool` | ~µs | none | drop/keep decisions (clipboards, prompts) |
| `scan(&str) -> Vec<Finding>` | regex pass | `regex` (feature `rules`) | reporting, redaction, dashboards |

The bool tier deliberately errs toward *dropping* (false positives are cheap);
the rule tier is tuned for a *low false-positive rate* (findings page someone).

## License

MIT OR Apache-2.0, at your option.
