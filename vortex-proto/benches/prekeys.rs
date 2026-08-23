use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use std::hint::black_box;
use vortex_proto::hex::encode::encode;
use vortex_proto::prekey::bundle::render::{bundle_list, bundle_response};
use vortex_proto::prekey::bundle::stored::StoredBundle;
use vortex_proto::prekey::publish::parse;
use vortex_proto::prekey::publish::request::PublishRequest;
use vortex_proto::verify::dalek::DalekVerifier;
use vortex_proto::verify::enforcement::Enforcement;

fn payload(one_time: usize) -> String {
    let signer = SigningKey::from_bytes(&[9u8; 32]);
    let identity_key = [0x11u8; 32];
    let signed_prekey = [0x22u8; 32];
    let uploads: Vec<String> = (0..one_time)
        .map(|index| {
            format!(
                r#"{{"key_id":{index},"public_key":"{}"}}"#,
                encode(&[index as u8; 32])
            )
        })
        .collect();
    format!(
        r#"{{"identity_key":"{}","signed_prekey":"{}","signed_prekey_sig":"{}","signed_prekey_id":1,
            "identity_key_ed":"{}","identity_key_sig":"{}","supports_v2":true,
            "one_time_prekeys":[{}]}}"#,
        encode(&identity_key),
        encode(&signed_prekey),
        encode(&signer.sign(&signed_prekey).to_bytes()),
        encode(&signer.verifying_key().to_bytes()),
        encode(&signer.sign(&identity_key).to_bytes()),
        uploads.join(",")
    )
}

fn stored() -> StoredBundle {
    StoredBundle {
        device_id: Some(1),
        identity_key: vec![0x11; 32],
        signed_prekey: vec![0x22; 32],
        signed_prekey_sig: vec![0x33; 64],
        signed_prekey_id: 1,
        identity_key_ed: Some(vec![0x44; 32]),
        identity_key_sig: Some(vec![0x55; 64]),
        supports_v2: Some(true),
        device_x3dh_pub: Some(vec![0x66; 32]),
        device_sign_pub: Some(vec![0x77; 32]),
        device_cert_sig: Some(vec![0x88; 64]),
        client_device_id: Some("0123456789abcdef0123456789abcdef".to_string()),
        device_kyber_pub: Some(vec![0x99; 1184]),
        device_kyber_sig: Some(vec![0xaa; 64]),
        device_kyber_id: Some(0),
    }
}

fn publish(criterion: &mut Criterion) {
    let bare = payload(0);
    let batch = payload(100);
    let verifier = DalekVerifier;

    criterion.bench_function("publish_parse_no_one_time", |bencher| {
        bencher.iter(|| {
            let request = PublishRequest::from_json(black_box(&bare)).unwrap();
            parse(&request, Enforcement::Reject, &verifier).unwrap()
        })
    });

    criterion.bench_function("publish_parse_full_batch", |bencher| {
        bencher.iter(|| {
            let request = PublishRequest::from_json(black_box(&batch)).unwrap();
            parse(&request, Enforcement::Reject, &verifier).unwrap()
        })
    });
}

fn render(criterion: &mut Criterion) {
    let bundle = stored();
    let many: Vec<StoredBundle> = (0..8).map(|_| stored()).collect();

    criterion.bench_function("render_bundle_response", |bencher| {
        bencher.iter(|| bundle_response(black_box(1), black_box(&bundle)))
    });

    criterion.bench_function("render_bundle_list_of_eight", |bencher| {
        bencher.iter(|| bundle_list(black_box(1), black_box(&many)))
    });
}

criterion_group!(benches, publish, render);
criterion_main!(benches);
