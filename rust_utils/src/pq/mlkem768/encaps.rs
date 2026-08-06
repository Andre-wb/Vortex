use ml_kem::kem::Encapsulate;
use ml_kem::{EncapsulateDeterministic, B32};
use rand_core::OsRng;

use super::codec;

pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let ek = codec::encapsulation_key(public_key)?;
    let (ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| "encapsulation failed".to_string())?;
    Ok((ct.to_vec(), ss.to_vec()))
}

pub fn encapsulate_derand(public_key: &[u8], m: &B32) -> Result<(Vec<u8>, Vec<u8>), String> {
    let ek = codec::encapsulation_key(public_key)?;
    let (ct, ss) = ek
        .encapsulate_deterministic(m)
        .map_err(|_| "encapsulation failed".to_string())?;
    Ok((ct.to_vec(), ss.to_vec()))
}
