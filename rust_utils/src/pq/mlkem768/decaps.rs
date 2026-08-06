use ml_kem::kem::Decapsulate;

use super::codec;

pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let dk = codec::decapsulation_key(secret_key)?;
    let ct = codec::ciphertext(ciphertext)?;
    let ss = dk
        .decapsulate(&ct)
        .map_err(|_| "decapsulation failed".to_string())?;
    Ok(ss.to_vec())
}
