use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vortex_net::stealth;
use vortex_net::wire;

const NETWORK_KEY: &[u8] = b"vortex-network-secret-key-example";
const PUBKEY: &str = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44";

fn bench_encode(criterion: &mut Criterion) {
    criterion.bench_function("wire_encode_with_pubkey", |bencher| {
        bencher.iter(|| {
            wire::encode(
                black_box("workstation-01"),
                black_box(9000),
                black_box(Some(PUBKEY)),
            )
        });
    });
}

fn bench_decode(criterion: &mut Criterion) {
    let frame = wire::encode("workstation-01", 9000, Some(PUBKEY));
    criterion.bench_function("wire_decode_with_pubkey", |bencher| {
        bencher.iter(|| wire::decode(black_box(&frame), black_box("192.168.1.9"), black_box(9000)));
    });
}

fn bench_stealth(criterion: &mut Criterion) {
    let frame = wire::encode("workstation-01", 9000, Some(PUBKEY));
    let nonce = [7u8; 8];
    let sealed = stealth::seal(&frame, &nonce, NETWORK_KEY);

    criterion.bench_function("stealth_seal_payload", |bencher| {
        bencher
            .iter(|| stealth::seal(black_box(&frame), black_box(&nonce), black_box(NETWORK_KEY)));
    });
    criterion.bench_function("stealth_open_payload", |bencher| {
        bencher.iter(|| stealth::open(black_box(&sealed), black_box(NETWORK_KEY)));
    });
}

criterion_group!(benches, bench_encode, bench_decode, bench_stealth);
criterion_main!(benches);
