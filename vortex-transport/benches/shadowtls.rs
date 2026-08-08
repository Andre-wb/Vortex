use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use vortex_transport::random::fixed_random::FixedRandom;
use vortex_transport::shadowtls::guard::ShadowTls;
use vortex_transport::shadowtls::secret::keyring::Keyring;
use vortex_transport::shadowtls::secret::password_key;
use vortex_transport::shadowtls::session::role::Role;
use vortex_transport::shadowtls::switch::{matcher, sealer, session_id::SessionId};
use vortex_transport::tls::record::scanner::{RecordScanner, ScanStep};

const PASSWORD: &[u8] = b"benchmark-password";
const SERVER_RANDOM: [u8; 32] = [0x77; 32];
const RECORDS_PER_STREAM: usize = 64;
const RECORD_PAYLOAD: usize = 1024;

fn session_id() -> SessionId {
    SessionId::from_bytes([0x02; 16])
}

fn record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type, 0x03, 0x03];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn stream_of_records() -> Vec<u8> {
    let payload = vec![0x5A; RECORD_PAYLOAD];
    let mut out = Vec::new();
    for _ in 0..RECORDS_PER_STREAM {
        out.extend_from_slice(&record(0x17, &payload));
    }
    out
}

fn switch_payload(padding: usize) -> Vec<u8> {
    let key = password_key::derive(PASSWORD).unwrap();
    sealer::payload(&key, &SERVER_RANDOM, &session_id(), &vec![0u8; padding])
}

fn scanner(criterion: &mut Criterion) {
    let stream = stream_of_records();
    criterion.bench_function("scan_records", |bencher| {
        bencher.iter(|| {
            let mut scanner = RecordScanner::new();
            scanner.push(&stream);
            let mut seen = 0usize;
            while let ScanStep::Record(_) = scanner.next_record() {
                seen += 1;
            }
            seen
        })
    });
}

fn switch_matching(criterion: &mut Criterion) {
    let keyring = Keyring::new(PASSWORD, b"");
    let hit = switch_payload(256);
    let miss = vec![0x00; hit.len()];

    criterion.bench_function("match_switch_hit", |bencher| {
        bencher.iter(|| matcher::match_record(&keyring, Some(&SERVER_RANDOM), 0x17, &hit))
    });
    criterion.bench_function("match_switch_miss", |bencher| {
        bencher.iter(|| matcher::match_record(&keyring, Some(&SERVER_RANDOM), 0x17, &miss))
    });
}

fn sealing(criterion: &mut Criterion) {
    let guard = ShadowTls::new(PASSWORD, b"");
    let random = FixedRandom::new(vec![]).with_filler(0x11);
    criterion.bench_function("seal_switch", |bencher| {
        bencher.iter(|| guard.seal_switch(&SERVER_RANDOM, &session_id(), &random))
    });
}

fn data_stream(criterion: &mut Criterion) {
    let guard = ShadowTls::new(PASSWORD, b"");
    for size in [1024usize, 16384] {
        let data = vec![0x5A; size];
        criterion.bench_function(&format!("wrap_{size}"), |bencher| {
            bencher.iter_batched(
                || {
                    guard
                        .stream(&SERVER_RANDOM, &session_id(), Role::Server)
                        .unwrap()
                },
                |mut stream| stream.wrap(&data),
                BatchSize::SmallInput,
            )
        });

        let mut sender = guard
            .stream(&SERVER_RANDOM, &session_id(), Role::Server)
            .unwrap();
        let frame = sender.wrap(&data);
        criterion.bench_function(&format!("unwrap_{size}"), |bencher| {
            bencher.iter_batched(
                || {
                    guard
                        .stream(&SERVER_RANDOM, &session_id(), Role::Client)
                        .unwrap()
                },
                |mut stream| stream.unwrap(&frame),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(benches, scanner, switch_matching, sealing, data_stream);
criterion_main!(benches);
