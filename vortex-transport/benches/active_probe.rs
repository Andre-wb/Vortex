use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vortex_transport::active_probe::detector::ActiveProbeDetector;
use vortex_transport::active_probe::request::head::RequestHead;
use vortex_transport::active_probe::request::headers::HeaderSet;

const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

fn browser() -> HeaderSet {
    HeaderSet::of([
        ("host", "vortex.example"),
        ("connection", "keep-alive"),
        ("sec-ch-ua", "\"Chromium\";v=\"120\""),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"Windows\""),
        ("accept", "*/*"),
        ("user-agent", CHROME),
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-dest", "empty"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-language", "ru-RU,ru;q=0.9"),
        ("cookie", "session=abcdef0123456789; _ga=GA1.2.1.2"),
    ])
}

fn machine() -> HeaderSet {
    HeaderSet::of([
        ("host", "vortex.example"),
        ("accept", "*/*"),
        ("accept-encoding", "gzip, deflate"),
        ("connection", "keep-alive"),
        ("user-agent", "python-httpx/0.28.1"),
    ])
}

fn scanner() -> HeaderSet {
    HeaderSet::of([("user-agent", "sqlmap/1.7.11#stable (https://sqlmap.org)")])
}

fn benchmarks(criterion: &mut Criterion) {
    let detector = ActiveProbeDetector::default();

    let allowed = RequestHead::new("203.0.113.7", "GET", "/api/chats", browser());
    criterion.bench_function("inspect/browser", |bencher| {
        let mut tick = 0.0f64;
        bencher.iter(|| {
            tick += 1.0;
            black_box(detector.inspect(black_box(&allowed), tick))
        })
    });

    let exempt = RequestHead::new("203.0.113.7", "GET", "/health", machine());
    criterion.bench_function("inspect/exempt route", |bencher| {
        bencher.iter(|| black_box(detector.inspect(black_box(&exempt), 1000.0)))
    });

    let local = RequestHead::new("192.168.1.5", "GET", "/api/chats", browser());
    criterion.bench_function("inspect/local peer", |bencher| {
        bencher.iter(|| black_box(detector.inspect(black_box(&local), 1000.0)))
    });

    let probe = RequestHead::new("203.0.113.7", "GET", "/api/chats", scanner());
    criterion.bench_function("inspect/probe", |bencher| {
        let mut tick = 0.0f64;
        bencher.iter(|| {
            tick += 1.0;
            black_box(detector.inspect(black_box(&probe), tick))
        })
    });

    let suspected = RequestHead::new("109.124.1.1", "GET", "/api/chats", browser());
    criterion.bench_function("inspect/suspected network", |bencher| {
        let mut tick = 0.0f64;
        bencher.iter(|| {
            tick += 1.0;
            black_box(detector.inspect(black_box(&suspected), tick))
        })
    });

    let repeated = RequestHead::new("203.0.113.7", "GET", "/api/chats", browser());
    criterion.bench_function("inspect/replay of the same request", |bencher| {
        bencher.iter(|| black_box(detector.inspect(black_box(&repeated), 5000.0)))
    });
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
