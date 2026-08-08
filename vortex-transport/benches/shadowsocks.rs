use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use vortex_transport::random::os_random::OsRandom;
use vortex_transport::shadowsocks::guard::Shadowsocks;
use vortex_transport::shadowsocks::schedule::salt::SessionSalt;
use vortex_transport::shadowsocks::session::Session;

const PASSWORD: &[u8] = b"benchmark-password";
const HOST: &str = "www.example.com";
const PORT: u16 = 443;

fn guard() -> Shadowsocks {
    Shadowsocks::new(PASSWORD, b"")
}

fn crowded_guard(passwords: usize) -> Shadowsocks {
    let mut guard = guard();
    for index in 0..passwords {
        guard.add_password(format!("extra-{index}").as_bytes());
    }
    guard
}

fn sessions(guard: &Shadowsocks, random: &OsRandom) -> (Session, Session) {
    let handshake = guard.connect(HOST, PORT, b"", random).unwrap();
    let accepted = guard.accept(&handshake.stream()).accepted().unwrap();
    (handshake.session, accepted.session)
}

fn handshake(c: &mut Criterion) {
    let guard = guard();
    let random = OsRandom::new();
    let mut group = c.benchmark_group("shadowsocks/handshake");
    group.bench_function("connect_domain", |b| {
        b.iter(|| black_box(guard.connect(HOST, PORT, b"", &random)))
    });
    group.bench_function("connect_ipv4", |b| {
        b.iter(|| black_box(guard.connect("93.184.216.34", PORT, b"", &random)))
    });
    let payload = vec![0x5Au8; 1024];
    group.bench_function("connect_carrying_1k", |b| {
        b.iter(|| black_box(guard.connect(HOST, PORT, &payload, &random)))
    });
    let salt = SessionSalt::from_bytes([0x11; 32]);
    group.bench_function("connect_without_drawing_randomness", |b| {
        b.iter(|| black_box(guard.connect_with(HOST, PORT, b"", salt, &[])))
    });
    group.finish();
}

fn accepting(c: &mut Criterion) {
    let guard = guard();
    let random = OsRandom::new();
    let known = guard.connect(HOST, PORT, b"", &random).unwrap().stream();
    let stranger = Shadowsocks::new(b"another-password", b"")
        .connect(HOST, PORT, b"", &random)
        .unwrap()
        .stream();
    let crowded = crowded_guard(64);

    let mut group = c.benchmark_group("shadowsocks/accept");
    group.bench_function("known_password", |b| {
        b.iter(|| black_box(guard.accept(&known)))
    });
    group.bench_function("unknown_password", |b| {
        b.iter(|| black_box(guard.accept(&stranger)))
    });
    group.bench_function("unknown_password_65_keys", |b| {
        b.iter(|| black_box(crowded.accept(&stranger)))
    });
    let cut = &known[..known.len() - 1];
    group.bench_function("incomplete_request", |b| {
        b.iter(|| black_box(guard.accept(cut)))
    });
    group.finish();
}

fn frames(c: &mut Criterion) {
    let guard = guard();
    let random = OsRandom::new();
    let mut group = c.benchmark_group("shadowsocks/frames");
    for size in [64usize, 1024, 16384] {
        let data = vec![0x41u8; size];
        group.bench_with_input(BenchmarkId::new("seal", size), &data, |b, data| {
            let (mut client, _) = sessions(&guard, &random);
            b.iter(|| black_box(client.seal(data)))
        });
        group.bench_with_input(BenchmarkId::new("open", size), &data, |b, data| {
            let (mut client, mut server) = sessions(&guard, &random);
            b.iter_batched(
                || client.seal(data),
                |frame| black_box(server.drain(&frame)),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.bench_function("step_on_a_stranger", |b| {
        let (_, mut server) = sessions(&guard, &random);
        let noise = vec![0x5Au8; 512];
        b.iter(|| black_box(server.step(&noise)))
    });
    group.finish();
}

criterion_group!(benches, handshake, accepting, frames);
criterion_main!(benches);
