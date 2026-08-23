use crate::ports::random_source::RandomSource;
use crate::stealth::key::derive_key;
use crate::stealth::{KEY_LEN, MIN_ENVELOPE_LEN, NONCE_LEN};

fn keystream_byte(key: &[u8; KEY_LEN], nonce: &[u8], index: usize) -> u8 {
    key[(index + nonce[index % NONCE_LEN] as usize) % KEY_LEN]
}

pub fn seal(payload: &[u8], nonce: &[u8; NONCE_LEN], network_key: &[u8]) -> Vec<u8> {
    let key = derive_key(network_key);
    let mut out = Vec::with_capacity(NONCE_LEN + payload.len());
    out.extend_from_slice(nonce);
    for (index, byte) in payload.iter().enumerate() {
        out.push(byte ^ keystream_byte(&key, nonce, index));
    }
    out
}

pub fn seal_with(payload: &[u8], random: &dyn RandomSource, network_key: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    random.fill_bytes(&mut nonce);
    seal(payload, &nonce, network_key)
}

pub fn open(data: &[u8], network_key: &[u8]) -> Option<Vec<u8>> {
    if data.len() < MIN_ENVELOPE_LEN {
        return None;
    }
    let nonce = &data[..NONCE_LEN];
    let ciphertext = &data[NONCE_LEN..];
    let key = derive_key(network_key);
    let mut out = Vec::with_capacity(ciphertext.len());
    for (index, byte) in ciphertext.iter().enumerate() {
        out.push(byte ^ keystream_byte(&key, nonce, index));
    }
    Some(out)
}
