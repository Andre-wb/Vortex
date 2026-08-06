use ml_kem::array::Array;
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, B32};

use super::sizes;

pub type EncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;
pub type DecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;

pub fn encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey, String> {
    let encoded: Encoded<EncapsulationKey> =
        Array::try_from(bytes).map_err(|_| length_error("public key", sizes::PUBLIC_KEY))?;
    Ok(EncapsulationKey::from_bytes(&encoded))
}

pub fn decapsulation_key(bytes: &[u8]) -> Result<DecapsulationKey, String> {
    let encoded: Encoded<DecapsulationKey> =
        Array::try_from(bytes).map_err(|_| length_error("secret key", sizes::SECRET_KEY))?;
    Ok(DecapsulationKey::from_bytes(&encoded))
}

pub fn ciphertext(bytes: &[u8]) -> Result<Ciphertext<MlKem768>, String> {
    Array::try_from(bytes).map_err(|_| length_error("ciphertext", sizes::CIPHERTEXT))
}

pub fn seed(bytes: &[u8], label: &str) -> Result<B32, String> {
    Array::try_from(bytes).map_err(|_| length_error(label, sizes::SEED))
}

fn length_error(label: &str, expected: usize) -> String {
    format!("{label} must be {expected} bytes")
}
