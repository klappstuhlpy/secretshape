//! Performance claims need numbers. Targets (from the plan): Tier 1 < 1 µs on typical
//! clipboard content; Tier 2 < 50 µs per 8 KiB line. Results are recorded in the README —
//! measured, not assumed.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secretshape::{is_probably_secret, scan, Scanner};

fn tier1(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_probably_secret");
    let short_prose = "Guten Morgen, wie geht es dir?";
    let url = "https://github.com/klappstuhlpy/funke/releases/tag/v0.3.1";
    let token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
    let opaque = "Xk7pQm2Rv9Ls4Tz8Wn3Yb6Hd"; // hits the entropy path, the worst case
    let paste_1k = "The deploy log said: retry scheduled, backoff 250ms, attempt 4/5. ".repeat(16);

    group.bench_function("short_prose", |b| b.iter(|| is_probably_secret(black_box(short_prose))));
    group.bench_function("url", |b| b.iter(|| is_probably_secret(black_box(url))));
    group.bench_function("vendor_token", |b| b.iter(|| is_probably_secret(black_box(token))));
    group.bench_function("opaque_token_entropy_path", |b| {
        b.iter(|| is_probably_secret(black_box(opaque)))
    });
    group.bench_function("paste_1kib", |b| b.iter(|| is_probably_secret(black_box(&paste_1k))));
    group.finish();
}

fn tier2(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan");
    // A clean 8 KiB line: realistic log/code text, no secrets.
    let clean_8k = "2026-07-14T12:30:45Z INFO request served path=/api/v1/guilds status=200 dur=12ms ".repeat(102);
    assert!(clean_8k.len() >= 8 * 1024);
    // A dirty line: same shape, with two credentials buried in it.
    let dirty_8k = format!(
        "{}token=ghp_16C7e42F292c6912E7710c838347Ae178B4a dsn=postgres://u:p@h:5432/db {}",
        &clean_8k[..4096],
        &clean_8k[..4096]
    );

    group.bench_function("clean_8kib_line", |b| b.iter(|| scan(black_box(&clean_8k))));
    group.bench_function("dirty_8kib_line", |b| b.iter(|| scan(black_box(&dirty_8k))));

    let heuristic_scanner = Scanner::new().include_heuristics(true);
    group.bench_function("clean_8kib_line_with_heuristics", |b| {
        b.iter(|| heuristic_scanner.scan(black_box(&clean_8k)))
    });
    group.finish();
}

fn redaction(c: &mut Criterion) {
    let clean = "cache warmed in 32ms, 512 entries";
    let dirty = "refresh failed for token ghp_16C7e42F292c6912E7710c838347Ae178B4a, retrying";
    let mut group = c.benchmark_group("redact");
    group.bench_function("clean_line_borrowed", |b| {
        b.iter(|| secretshape::redact(black_box(clean)))
    });
    group.bench_function("dirty_line", |b| b.iter(|| secretshape::redact(black_box(dirty))));
    group.finish();
}

criterion_group!(benches, tier1, tier2, redaction);
criterion_main!(benches);
