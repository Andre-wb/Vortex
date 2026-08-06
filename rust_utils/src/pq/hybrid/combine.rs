use hkdf::Hkdf;
use sha2::Sha256;

pub fn combine(x25519_shared: &[u8], kyber_shared: &[u8], info: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(x25519_shared.len() + kyber_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kyber_shared);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 with 32-byte output length is valid");
    okm
}
