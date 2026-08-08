use criterion::{criterion_group, criterion_main, Criterion};
use vortex_transport::trojan::guard::Trojan;
use vortex_transport::trojan::request::probe;

const PASSWORD: &[u8] = b"benchmark-password";
const PAYLOAD: usize = 1024;

fn guard() -> Trojan {
    Trojan::new(PASSWORD, b"")
}

fn crowded_guard(passwords: usize) -> Trojan {
    let mut guard = guard();
    for index in 0..passwords {
        guard.add_password(format!("extra-{index}").as_bytes());
    }
    guard
}

fn request(guard: &Trojan, host: &str) -> Vec<u8> {
    guard
        .encode_request(host, 443, &vec![0x5A; PAYLOAD])
        .unwrap()
}

fn encoding(criterion: &mut Criterion) {
    let guard = guard();
    let payload = vec![0x5A; PAYLOAD];
    criterion.bench_function("encode_request_domain", |bencher| {
        bencher.iter(|| guard.encode_request("www.example.com", 443, &payload))
    });
    criterion.bench_function("encode_request_ipv4", |bencher| {
        bencher.iter(|| guard.encode_request("93.184.216.34", 443, &payload))
    });
}

fn decoding(criterion: &mut Criterion) {
    let guard = guard();
    let domain = request(&guard, "www.example.com");
    let ipv4 = request(&guard, "93.184.216.34");
    let stranger = request(&Trojan::new(b"another-password", b""), "www.example.com");

    criterion.bench_function("decode_request_domain", |bencher| {
        bencher.iter(|| guard.decode_request(&domain))
    });
    criterion.bench_function("decode_request_ipv4", |bencher| {
        bencher.iter(|| guard.decode_request(&ipv4))
    });
    criterion.bench_function("decode_request_unauthorized", |bencher| {
        bencher.iter(|| guard.decode_request(&stranger))
    });
}

fn keyring_size(criterion: &mut Criterion) {
    for passwords in [0usize, 64] {
        let guard = crowded_guard(passwords);
        let stranger = request(&Trojan::new(b"another-password", b""), "www.example.com");
        criterion.bench_function(
            &format!("decode_request_miss_{passwords}_extra"),
            |bencher| bencher.iter(|| guard.decode_request(&stranger)),
        );
    }
}

fn probing(criterion: &mut Criterion) {
    let guard = guard();
    let trojan = request(&guard, "www.example.com");
    let http = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n".to_vec();
    criterion.bench_function("probe_trojan", |bencher| {
        bencher.iter(|| probe::probe(&trojan))
    });
    criterion.bench_function("probe_http", |bencher| bencher.iter(|| probe::probe(&http)));
}

criterion_group!(benches, encoding, decoding, keyring_size, probing);
criterion_main!(benches);
