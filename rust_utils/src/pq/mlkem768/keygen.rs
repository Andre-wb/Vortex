use ml_kem::{EncodedSizeUser, KemCore, MlKem768, B32};
use rand_core::OsRng;

pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
}

pub fn keygen_derand(d: &B32, z: &B32) -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate_deterministic(d, z);
    (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
}
