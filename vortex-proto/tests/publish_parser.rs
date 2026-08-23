use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use vortex_proto::hex::encode::encode;
use vortex_proto::prekey::limits::MAX_ONE_TIME_BATCH;
use vortex_proto::prekey::publish::parse;
use vortex_proto::prekey::publish::request::PublishRequest;
use vortex_proto::reject::rejection::Rejection;
use vortex_proto::verify::dalek::DalekVerifier;
use vortex_proto::verify::enforcement::Enforcement;

const IDENTITY_KEY: [u8; 32] = [0x11; 32];
const SIGNED_PREKEY: [u8; 32] = [0x22; 32];

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn well_signed() -> Value {
    let key = signer();
    json!({
        "identity_key": encode(&IDENTITY_KEY),
        "signed_prekey": encode(&SIGNED_PREKEY),
        "signed_prekey_sig": encode(&key.sign(&SIGNED_PREKEY).to_bytes()),
        "signed_prekey_id": 1,
        "identity_key_ed": encode(&key.verifying_key().to_bytes()),
        "identity_key_sig": encode(&key.sign(&IDENTITY_KEY).to_bytes()),
    })
}

fn parse_value(value: &Value, enforcement: Enforcement) -> Result<(), Rejection> {
    let request = PublishRequest::from_json(&value.to_string()).unwrap();
    parse(&request, enforcement, &DalekVerifier).map(|_| ())
}

fn refusal(value: &Value) -> Rejection {
    parse_value(value, Enforcement::Reject).unwrap_err()
}

#[test]
fn a_well_signed_bundle_is_accepted() {
    let request = PublishRequest::from_json(&well_signed().to_string()).unwrap();
    let parsed = parse(&request, Enforcement::Reject, &DalekVerifier).unwrap();
    assert!(parsed.complaints.is_empty());
    assert_eq!(parsed.account.signed_prekey_id, 1);
    assert_eq!(parsed.account.identity_key.as_bytes(), &IDENTITY_KEY);
}

#[test]
fn a_non_hex_account_key_is_named_before_its_length() {
    let mut value = well_signed();
    value["identity_key"] = json!("zz".repeat(32));
    assert_eq!(refusal(&value), Rejection::key_hex());
}

#[test]
fn hex_of_every_account_key_is_checked_before_any_length() {
    let mut value = well_signed();
    value["identity_key"] = json!("11");
    value["signed_prekey_sig"] = json!("zz".repeat(64));
    assert_eq!(refusal(&value), Rejection::key_hex());
}

#[test]
fn an_account_key_of_the_wrong_size_is_refused_by_length() {
    let mut value = well_signed();
    value["signed_prekey"] = json!(encode(&[0x22; 31]));
    assert_eq!(refusal(&value), Rejection::key_lengths());
}

#[test]
fn a_broken_identity_key_is_reported_apart_from_the_account_keys() {
    let mut value = well_signed();
    value["identity_key_ed"] = json!("zz".repeat(32));
    assert_eq!(refusal(&value), Rejection::identity_hex());

    let mut value = well_signed();
    value["identity_key_ed"] = json!(encode(&[0x33; 31]));
    assert_eq!(refusal(&value), Rejection::identity_lengths());
}

#[test]
fn a_binding_signature_without_an_identity_key_is_ignored_entirely() {
    let mut value = well_signed();
    value["identity_key_ed"] = Value::Null;
    value["identity_key_sig"] = json!("nonsense");
    let request = PublishRequest::from_json(&value.to_string()).unwrap();
    let parsed = parse(&request, Enforcement::WarnOnly, &DalekVerifier).unwrap();
    assert!(parsed.account.identity_key_sig.is_none());
    assert_eq!(parsed.account.identity_key_ed, None);
}

#[test]
fn a_broken_device_identity_is_reported_apart_from_the_identity_key() {
    let mut value = well_signed();
    value["device_x3dh_pub"] = json!("zz".repeat(32));
    assert_eq!(refusal(&value), Rejection::device_hex());

    let mut value = well_signed();
    value["device_cert_sig"] = json!(encode(&[0x44; 63]));
    assert_eq!(refusal(&value), Rejection::device_lengths());
}

#[test]
fn a_broken_kyber_prekey_is_reported_apart_from_the_device_identity() {
    let mut value = well_signed();
    value["device_kyber_pub"] = json!("zz".repeat(1184));
    assert_eq!(refusal(&value), Rejection::kyber_hex());

    let mut value = well_signed();
    value["device_kyber_pub"] = json!(encode(&[0x55; 1183]));
    assert_eq!(refusal(&value), Rejection::kyber_lengths());
}

#[test]
fn a_negative_identifier_is_refused_before_any_key_is_read() {
    let mut value = well_signed();
    value["signed_prekey_id"] = json!(-1);
    value["identity_key"] = json!("zz");
    assert_eq!(refusal(&value), Rejection::signed_prekey_id());

    let mut value = well_signed();
    value["device_kyber_id"] = json!(-1);
    assert_eq!(refusal(&value), Rejection::kyber_prekey_id());
}

#[test]
fn a_batch_larger_than_the_limit_is_refused_whole() {
    let uploads: Vec<Value> = (0..=MAX_ONE_TIME_BATCH)
        .map(|index| json!({"key_id": index, "public_key": encode(&[0x66; 32])}))
        .collect();
    let mut value = well_signed();
    value["one_time_prekeys"] = json!(uploads);
    assert_eq!(
        refusal(&value),
        Rejection::one_time_batch(MAX_ONE_TIME_BATCH)
    );
}

#[test]
fn a_batch_exactly_at_the_limit_is_accepted() {
    let uploads: Vec<Value> = (0..MAX_ONE_TIME_BATCH)
        .map(|index| json!({"key_id": index, "public_key": encode(&[0x66; 32])}))
        .collect();
    let mut value = well_signed();
    value["one_time_prekeys"] = json!(uploads);
    let request = PublishRequest::from_json(&value.to_string()).unwrap();
    let parsed = parse(&request, Enforcement::Reject, &DalekVerifier).unwrap();
    assert_eq!(parsed.one_time.len(), MAX_ONE_TIME_BATCH);
}

#[test]
fn one_malformed_key_refuses_the_whole_batch_and_names_it() {
    let mut value = well_signed();
    value["one_time_prekeys"] = json!([
        {"key_id": 1, "public_key": encode(&[0x66; 32])},
        {"key_id": 2, "public_key": "zz".repeat(32)},
        {"key_id": 3, "public_key": encode(&[0x77; 32])},
    ]);
    assert_eq!(refusal(&value), Rejection::one_time_hex(2));

    let mut value = well_signed();
    value["one_time_prekeys"] = json!([
        {"key_id": 5, "public_key": encode(&[0x66; 31])},
    ]);
    assert_eq!(refusal(&value), Rejection::one_time_length(5));
}

#[test]
fn a_malformed_kyber_key_is_refused_on_its_own_wording() {
    let mut value = well_signed();
    value["one_time_kyber_prekeys"] = json!([
        {"key_id": 1, "public_key": encode(&[0x66; 1184])},
        {"key_id": 2, "public_key": encode(&[0x66; 32])},
    ]);
    assert_eq!(refusal(&value), Rejection::kyber_one_time_length(2));

    let mut value = well_signed();
    value["one_time_kyber_prekeys"] = json!([
        {"key_id": 3, "public_key": "zz".repeat(1184)},
    ]);
    assert_eq!(refusal(&value), Rejection::kyber_one_time_hex(3));
}

#[test]
fn a_batch_of_well_formed_keys_is_kept_in_the_order_it_arrived() {
    let mut value = well_signed();
    value["one_time_prekeys"] = json!([
        {"key_id": 9, "public_key": encode(&[0x66; 32])},
        {"key_id": 4, "public_key": encode(&[0x77; 32])},
    ]);
    let request = PublishRequest::from_json(&value.to_string()).unwrap();
    let parsed = parse(&request, Enforcement::Reject, &DalekVerifier).unwrap();

    assert_eq!(parsed.one_time.len(), 2);
    assert_eq!(parsed.one_time[0].key_id, 9);
    assert_eq!(parsed.one_time[1].key_id, 4);
    assert_eq!(parsed.one_time[0].public.as_bytes(), &[0x66; 32]);
}
