use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use vortex_transport::obfuscation::guard::Obfuscation;
use vortex_transport::obfuscation::normalizer::config::NormalizerConfig;
use vortex_transport::obfuscation::normalizer::traffic::TrafficNormalizer;
use vortex_transport::obfuscation::padding::web_sizes::WEB_SIZES;
use vortex_transport::random::os_random::OsRandom;
use vortex_transport::vortex_obfs::config::VortexObfsConfig;
use vortex_transport::vortex_obfs::guard::VortexObfs;
use vortex_transport::vortex_obfs::session::Session;

fn sessions(guard: &VortexObfs, random: &OsRandom) -> (Session, Session) {
    let handshake = guard.begin(random).unwrap();
    let responder = guard.accept(handshake.prologue()).unwrap();
    (handshake.session, responder)
}

fn padding(c: &mut Criterion) {
    let guard = Obfuscation::default();
    let random = OsRandom::new();
    let mut group = c.benchmark_group("obfuscation/padding");
    for size in [64usize, 1024, 16384] {
        let data = vec![0x41u8; size];
        group.bench_with_input(BenchmarkId::new("pad", size), &data, |b, data| {
            b.iter(|| black_box(guard.pad(data, None, &random)))
        });
        let envelope = guard.pad(&data, None, &random).unwrap();
        group.bench_with_input(BenchmarkId::new("unpad", size), &envelope, |b, envelope| {
            b.iter(|| black_box(guard.unpad(envelope)))
        });
    }
    let data = vec![0x41u8; 1024];
    group.bench_function("pad_to_web_size", |b| {
        b.iter(|| black_box(guard.pad(&data, Some(&WEB_SIZES), &random)))
    });
    group.finish();
}

fn timing(c: &mut Criterion) {
    let guard = Obfuscation::default();
    let random = OsRandom::new();
    let mut group = c.benchmark_group("obfuscation/timing");
    group.bench_function("delay", |b| b.iter(|| black_box(guard.delay(&random))));
    group.bench_function("interval", |b| {
        b.iter(|| black_box(guard.interval(30.0, 0.5, &random)))
    });
    group.finish();
}

fn normalizer(c: &mut Criterion) {
    let mut group = c.benchmark_group("obfuscation/normalizer");
    group.bench_function("padding_needed", |b| {
        let mut normalizer = TrafficNormalizer::new(NormalizerConfig::default());
        let mut now = 0.0f64;
        b.iter(|| {
            now += 0.1;
            black_box(normalizer.padding_needed(now))
        })
    });
    group.finish();
}

fn frames(c: &mut Criterion) {
    let guard = VortexObfs::new(b"benchmark-secret");
    let config = VortexObfsConfig::default();
    let random = OsRandom::new();
    let mut group = c.benchmark_group("vortex_obfs/frame");
    for size in [64usize, 1024, 16384] {
        let data = vec![0x41u8; size];
        group.bench_with_input(BenchmarkId::new("wrap", size), &data, |b, data| {
            let (mut initiator, _) = sessions(&guard, &random);
            b.iter(|| black_box(initiator.wrap(data, &config, &random)))
        });
        group.bench_with_input(BenchmarkId::new("unwrap", size), &data, |b, data| {
            let (mut initiator, mut responder) = sessions(&guard, &random);
            b.iter_batched(
                || initiator.wrap(data, &config, &random),
                |frame| black_box(responder.unwrap(&frame)),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.bench_function("handshake", |b| {
        b.iter(|| {
            let handshake = guard.begin(&random).unwrap();
            black_box(guard.accept(handshake.prologue()))
        })
    });
    group.bench_function("step_on_a_stranger", |b| {
        let (_, mut responder) = sessions(&guard, &random);
        let noise = vec![0x5Au8; 512];
        b.iter(|| black_box(responder.step(&noise)))
    });
    group.finish();
}

criterion_group!(benches, padding, timing, normalizer, frames);
criterion_main!(benches);
