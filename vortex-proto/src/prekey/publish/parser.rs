use crate::hex::decode::decode;
use crate::hex::error::HexError;
use crate::key::ed25519_public::{Ed25519Public, ED25519_PUBLIC_LEN};
use crate::key::ed25519_signature::{Ed25519Signature, ED25519_SIGNATURE_LEN};
use crate::key::kyber_public::{KyberPublic, KYBER_PUBLIC_LEN};
use crate::key::x25519_public::{X25519Public, X25519_PUBLIC_LEN};
use crate::prekey::identity::account::AccountIdentity;
use crate::prekey::identity::device::DeviceIdentity;
use crate::prekey::identity::kyber::DeviceKyberPreKey;
use crate::prekey::limits::MAX_ONE_TIME_BATCH;
use crate::prekey::publish::one_time::OneTimePreKey;
use crate::prekey::publish::one_time_kyber::OneTimeKyberPreKey;
use crate::prekey::publish::parsed::ParsedPublish;
use crate::prekey::publish::request::PublishRequest;
use crate::reject::rejection::Rejection;
use crate::verify::complaint::Complaint;
use crate::verify::enforcement::Enforcement;
use crate::verify::verifier::SignatureVerifier;

pub fn parse(
    request: &PublishRequest,
    enforcement: Enforcement,
    verifier: &dyn SignatureVerifier,
) -> Result<ParsedPublish, Rejection> {
    check_shape(request)?;

    let identity_key_bytes = hex_bytes(&request.identity_key, Rejection::key_hex)?;
    let signed_prekey_bytes = hex_bytes(&request.signed_prekey, Rejection::key_hex)?;
    let signed_prekey_sig_bytes = hex_bytes(&request.signed_prekey_sig, Rejection::key_hex)?;

    let identity_key = X25519Public::from_bytes(
        sized::<X25519_PUBLIC_LEN>(&identity_key_bytes).ok_or_else(Rejection::key_lengths)?,
    );
    let signed_prekey = X25519Public::from_bytes(
        sized::<X25519_PUBLIC_LEN>(&signed_prekey_bytes).ok_or_else(Rejection::key_lengths)?,
    );
    let signed_prekey_sig = Ed25519Signature::from_bytes(
        sized::<ED25519_SIGNATURE_LEN>(&signed_prekey_sig_bytes)
            .ok_or_else(Rejection::key_lengths)?,
    );

    let (identity_key_ed, identity_key_sig) = parse_account_ed25519(request)?;

    let mut complaints = Vec::new();
    verify_account(
        &identity_key,
        &signed_prekey,
        &signed_prekey_sig,
        identity_key_ed.as_ref(),
        identity_key_sig.as_ref(),
        enforcement,
        verifier,
        &mut complaints,
    )?;

    let device = parse_device(request)?;
    verify_device_key(&device, verifier)?;
    let kyber = parse_kyber(request)?;
    verify_kyber(&device, &kyber, enforcement, verifier, &mut complaints)?;

    let one_time = collect_one_time(request)?;
    let one_time_kyber = collect_one_time_kyber(request)?;

    Ok(ParsedPublish {
        account: AccountIdentity {
            identity_key,
            signed_prekey,
            signed_prekey_sig,
            signed_prekey_id: request.signed_prekey_id,
            identity_key_ed,
            identity_key_sig,
        },
        device,
        kyber,
        supports_v2: request.supports_v2,
        one_time,
        one_time_kyber,
        complaints,
    })
}

fn check_shape(request: &PublishRequest) -> Result<(), Rejection> {
    if request.signed_prekey_id < 0 {
        return Err(Rejection::signed_prekey_id());
    }
    if request.device_kyber_id.is_some_and(|value| value < 0) {
        return Err(Rejection::kyber_prekey_id());
    }
    if request.one_time_prekeys.len() > MAX_ONE_TIME_BATCH {
        return Err(Rejection::one_time_batch(MAX_ONE_TIME_BATCH));
    }
    if request.one_time_kyber_prekeys.len() > MAX_ONE_TIME_BATCH {
        return Err(Rejection::kyber_batch(MAX_ONE_TIME_BATCH));
    }
    Ok(())
}

fn parse_account_ed25519(
    request: &PublishRequest,
) -> Result<(Option<Ed25519Public>, Option<Ed25519Signature>), Rejection> {
    let Some(ed_text) = request.identity_key_ed.as_deref() else {
        return Ok((None, None));
    };

    let ed_bytes = hex_bytes(ed_text, Rejection::identity_hex)?;
    let sig_bytes = match request.identity_key_sig.as_deref() {
        Some(text) => Some(hex_bytes(text, Rejection::identity_hex)?),
        None => None,
    };

    let ed = Ed25519Public::from_bytes(
        sized::<ED25519_PUBLIC_LEN>(&ed_bytes).ok_or_else(Rejection::identity_lengths)?,
    );
    let signature = match sig_bytes {
        Some(bytes) => Some(Ed25519Signature::from_bytes(
            sized::<ED25519_SIGNATURE_LEN>(&bytes).ok_or_else(Rejection::identity_lengths)?,
        )),
        None => None,
    };
    Ok((Some(ed), signature))
}

#[allow(clippy::too_many_arguments)]
fn verify_account(
    identity_key: &X25519Public,
    signed_prekey: &X25519Public,
    signed_prekey_sig: &Ed25519Signature,
    identity_key_ed: Option<&Ed25519Public>,
    identity_key_sig: Option<&Ed25519Signature>,
    enforcement: Enforcement,
    verifier: &dyn SignatureVerifier,
    complaints: &mut Vec<Complaint>,
) -> Result<(), Rejection> {
    let Some(ed) = identity_key_ed else {
        return record(complaints, enforcement, Complaint::NoIdentityKey);
    };

    if !verifier.usable(ed) {
        return Err(Rejection::unusable_identity_key());
    }

    if !verifier.verify(ed, signed_prekey.as_bytes(), signed_prekey_sig) {
        record(complaints, enforcement, Complaint::SignedPreKeySignature)?;
    }

    match identity_key_sig {
        None => record(complaints, enforcement, Complaint::MissingIdentityBinding)?,
        Some(signature) => {
            if !verifier.verify(ed, identity_key.as_bytes(), signature) {
                record(complaints, enforcement, Complaint::IdentityBindingSignature)?;
            }
        }
    }
    Ok(())
}

fn parse_device(request: &PublishRequest) -> Result<DeviceIdentity, Rejection> {
    let x3dh_bytes = optional_hex(request.device_x3dh_pub.as_deref(), Rejection::device_hex)?;
    let sign_bytes = optional_hex(request.device_sign_pub.as_deref(), Rejection::device_hex)?;
    let cert_bytes = optional_hex(request.device_cert_sig.as_deref(), Rejection::device_hex)?;

    let x3dh_pub = match x3dh_bytes {
        Some(bytes) => Some(X25519Public::from_bytes(
            sized::<X25519_PUBLIC_LEN>(&bytes).ok_or_else(Rejection::device_lengths)?,
        )),
        None => None,
    };
    let sign_pub = match sign_bytes {
        Some(bytes) => Some(Ed25519Public::from_bytes(
            sized::<ED25519_PUBLIC_LEN>(&bytes).ok_or_else(Rejection::device_lengths)?,
        )),
        None => None,
    };
    let cert_sig = match cert_bytes {
        Some(bytes) => Some(Ed25519Signature::from_bytes(
            sized::<ED25519_SIGNATURE_LEN>(&bytes).ok_or_else(Rejection::device_lengths)?,
        )),
        None => None,
    };

    Ok(DeviceIdentity {
        x3dh_pub,
        sign_pub,
        cert_sig,
    })
}

fn verify_device_key(
    device: &DeviceIdentity,
    verifier: &dyn SignatureVerifier,
) -> Result<(), Rejection> {
    match device.sign_pub.as_ref() {
        Some(key) if !verifier.usable(key) => Err(Rejection::unusable_device_key()),
        _ => Ok(()),
    }
}

fn parse_kyber(request: &PublishRequest) -> Result<DeviceKyberPreKey, Rejection> {
    let public_bytes = optional_hex(request.device_kyber_pub.as_deref(), Rejection::kyber_hex)?;
    let signature_bytes = optional_hex(request.device_kyber_sig.as_deref(), Rejection::kyber_hex)?;

    let public = match public_bytes {
        Some(bytes) => Some(KyberPublic::from_bytes(
            sized::<KYBER_PUBLIC_LEN>(&bytes).ok_or_else(Rejection::kyber_lengths)?,
        )),
        None => None,
    };
    let signature = match signature_bytes {
        Some(bytes) => Some(Ed25519Signature::from_bytes(
            sized::<ED25519_SIGNATURE_LEN>(&bytes).ok_or_else(Rejection::kyber_lengths)?,
        )),
        None => None,
    };

    Ok(DeviceKyberPreKey {
        public,
        signature,
        id: request.device_kyber_id,
    })
}

fn verify_kyber(
    device: &DeviceIdentity,
    kyber: &DeviceKyberPreKey,
    enforcement: Enforcement,
    verifier: &dyn SignatureVerifier,
    complaints: &mut Vec<Complaint>,
) -> Result<(), Rejection> {
    let (Some(public), Some(sign_pub)) = (kyber.public.as_ref(), device.sign_pub.as_ref()) else {
        return Ok(());
    };

    match kyber.signature.as_ref() {
        None => record(complaints, enforcement, Complaint::MissingKyberSignature),
        Some(signature) => {
            if !verifier.verify(sign_pub, public.as_bytes().as_slice(), signature) {
                record(complaints, enforcement, Complaint::KyberSignature)
            } else {
                Ok(())
            }
        }
    }
}

fn collect_one_time(request: &PublishRequest) -> Result<Vec<OneTimePreKey>, Rejection> {
    request
        .one_time_prekeys
        .iter()
        .map(|upload| {
            X25519Public::parse_hex(&upload.public_key)
                .map(|public| OneTimePreKey {
                    key_id: upload.key_id,
                    public,
                })
                .map_err(|error| {
                    refuse_one_time(
                        &error,
                        upload.key_id,
                        Rejection::one_time_hex,
                        Rejection::one_time_length,
                    )
                })
        })
        .collect()
}

fn collect_one_time_kyber(request: &PublishRequest) -> Result<Vec<OneTimeKyberPreKey>, Rejection> {
    request
        .one_time_kyber_prekeys
        .iter()
        .map(|upload| {
            KyberPublic::parse_hex(&upload.public_key)
                .map(|public| OneTimeKyberPreKey {
                    key_id: upload.key_id,
                    public,
                })
                .map_err(|error| {
                    refuse_one_time(
                        &error,
                        upload.key_id,
                        Rejection::kyber_one_time_hex,
                        Rejection::kyber_one_time_length,
                    )
                })
        })
        .collect()
}

fn refuse_one_time(
    error: &HexError,
    key_id: i64,
    on_hex: fn(i64) -> Rejection,
    on_length: fn(i64) -> Rejection,
) -> Rejection {
    match error {
        HexError::NotHex => on_hex(key_id),
        HexError::Length { .. } => on_length(key_id),
    }
}

fn record(
    complaints: &mut Vec<Complaint>,
    enforcement: Enforcement,
    complaint: Complaint,
) -> Result<(), Rejection> {
    if enforcement.rejects() {
        return Err(Rejection::bad_request(complaint.detail()));
    }
    complaints.push(complaint);
    Ok(())
}

fn hex_bytes(text: &str, on_error: fn() -> Rejection) -> Result<Vec<u8>, Rejection> {
    decode(text).map_err(|_| on_error())
}

fn optional_hex(
    text: Option<&str>,
    on_error: fn() -> Rejection,
) -> Result<Option<Vec<u8>>, Rejection> {
    match text {
        Some(value) => Ok(Some(hex_bytes(value, on_error)?)),
        None => Ok(None),
    }
}

fn sized<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}
