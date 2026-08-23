use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use vortex_proto::hex::encode::encode;
use vortex_proto::prekey::publish::parse;
use vortex_proto::prekey::publish::request::PublishRequest;
use vortex_proto::reject::rejection::Rejection;
use vortex_proto::verify::complaint::Complaint;
use vortex_proto::verify::dalek::DalekVerifier;
use vortex_proto::verify::enforcement::Enforcement;

const IDENTITY_KEY: [u8; 32] = [0x11; 32];
const SIGNED_PREKEY: [u8; 32] = [0x22; 32];
const DEVICE_KYBER: [u8; 1184] = [0x33; 1184];

fn account() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn device() -> SigningKey {
    SigningKey::from_bytes(&[5u8; 32])
}

fn well_signed() -> Value {
    let key = account();
    json!({
        "identity_key": encode(&IDENTITY_KEY),
        "signed_prekey": encode(&SIGNED_PREKEY),
        "signed_prekey_sig": encode(&key.sign(&SIGNED_PREKEY).to_bytes()),
        "signed_prekey_id": 1,
        "identity_key_ed": encode(&key.verifying_key().to_bytes()),
        "identity_key_sig": encode(&key.sign(&IDENTITY_KEY).to_bytes()),
    })
}

fn with_kyber() -> Value {
    let signer = device();
    let mut value = well_signed();
    value["device_sign_pub"] = json!(encode(&signer.verifying_key().to_bytes()));
    value["device_kyber_pub"] = json!(encode(&DEVICE_KYBER));
    value["device_kyber_sig"] = json!(encode(&signer.sign(&DEVICE_KYBER).to_bytes()));
    value
}

fn complaints(value: &Value) -> Vec<Complaint> {
    let request = PublishRequest::from_json(&value.to_string()).unwrap();
    parse(&request, Enforcement::WarnOnly, &DalekVerifier)
        .unwrap()
        .complaints
}

fn refusal(value: &Value) -> Rejection {
    let request = PublishRequest::from_json(&value.to_string()).unwrap();
    parse(&request, Enforcement::Reject, &DalekVerifier).unwrap_err()
}

#[test]
fn a_bundle_signed_by_its_own_identity_raises_nothing() {
    assert!(complaints(&well_signed()).is_empty());
    assert!(complaints(&with_kyber()).is_empty());
}

#[test]
fn a_forged_signed_prekey_signature_stops_the_publish_when_enforced() {
    let mut value = well_signed();
    value["signed_prekey_sig"] = json!(encode(&[0x00; 64]));
    assert_eq!(
        refusal(&value).detail,
        Complaint::SignedPreKeySignature.detail()
    );
}

#[test]
fn a_forged_signature_only_warns_when_enforcement_is_off() {
    let mut value = well_signed();
    value["signed_prekey_sig"] = json!(encode(&[0x00; 64]));
    assert_eq!(complaints(&value), vec![Complaint::SignedPreKeySignature]);
}

#[test]
fn warn_only_collects_every_complaint_of_the_same_bundle() {
    let key = account();
    let mut value = well_signed();
    value["signed_prekey_sig"] = json!(encode(&[0x00; 64]));
    value["identity_key_sig"] = json!(encode(&key.sign(b"another message").to_bytes()));
    assert_eq!(
        complaints(&value),
        vec![
            Complaint::SignedPreKeySignature,
            Complaint::IdentityBindingSignature
        ]
    );
}

#[test]
fn a_missing_binding_signature_is_its_own_complaint() {
    let mut value = well_signed();
    value["identity_key_sig"] = Value::Null;
    assert_eq!(complaints(&value), vec![Complaint::MissingIdentityBinding]);
    assert_eq!(
        refusal(&value).detail,
        Complaint::MissingIdentityBinding.detail()
    );
}

#[test]
fn a_bundle_without_an_identity_key_can_be_verified_against_nothing() {
    let mut value = well_signed();
    value["identity_key_ed"] = Value::Null;
    value["identity_key_sig"] = Value::Null;
    assert_eq!(complaints(&value), vec![Complaint::NoIdentityKey]);
    assert_eq!(refusal(&value).detail, Complaint::NoIdentityKey.detail());
}

#[test]
fn a_kyber_prekey_signed_by_the_account_instead_of_the_device_is_refused() {
    let key = account();
    let mut value = with_kyber();
    value["device_kyber_sig"] = json!(encode(&key.sign(&DEVICE_KYBER).to_bytes()));
    assert_eq!(refusal(&value).detail, Complaint::KyberSignature.detail());
}

#[test]
fn a_kyber_prekey_without_a_signature_is_its_own_complaint() {
    let mut value = with_kyber();
    value["device_kyber_sig"] = Value::Null;
    assert_eq!(complaints(&value), vec![Complaint::MissingKyberSignature]);
}

#[test]
fn a_structurally_unusable_identity_key_is_refused_whatever_the_enforcement() {
    let mut value = well_signed();
    value["identity_key_ed"] = json!(encode(&[0u8; 32]));
    let request = PublishRequest::from_json(&value.to_string()).unwrap();
    for enforcement in [Enforcement::Reject, Enforcement::WarnOnly] {
        assert_eq!(
            parse(&request, enforcement, &DalekVerifier).unwrap_err(),
            Rejection::unusable_identity_key()
        );
    }
}

#[test]
fn a_structurally_unusable_device_key_is_refused_whatever_the_enforcement() {
    let mut value = with_kyber();
    value["device_sign_pub"] = json!(encode(&[0xffu8; 32]));
    let request = PublishRequest::from_json(&value.to_string()).unwrap();
    for enforcement in [Enforcement::Reject, Enforcement::WarnOnly] {
        assert_eq!(
            parse(&request, enforcement, &DalekVerifier).unwrap_err(),
            Rejection::unusable_device_key()
        );
    }
}

#[test]
fn a_kyber_prekey_is_left_alone_when_the_device_publishes_no_signing_key() {
    let mut value = with_kyber();
    value["device_sign_pub"] = Value::Null;
    value["device_kyber_sig"] = Value::Null;
    assert!(complaints(&value).is_empty());
}
