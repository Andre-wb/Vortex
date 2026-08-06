use crate::error::{Result, TransportError};
use crate::ports::random_source::RandomSource;
use crate::reality::auth::envelope::Envelope;
use crate::reality::auth::salt::{self, Salt};
use crate::reality::auth::sealed_auth::{SealedAuth, X25519_KEY_LEN};
use crate::reality::auth::{auth_key, nonce};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn seal(
    server_public: &[u8],
    envelope: &Envelope,
    random: &dyn RandomSource,
) -> Result<SealedAuth> {
    let mut secret_bytes = [0u8; X25519_KEY_LEN];
    random.fill_bytes(&mut secret_bytes);
    seal_with_ephemeral(
        server_public,
        envelope,
        secret_bytes,
        salt::generate(random),
    )
}

pub fn seal_with_ephemeral(
    server_public: &[u8],
    envelope: &Envelope,
    ephemeral_secret: [u8; X25519_KEY_LEN],
    salt: Salt,
) -> Result<SealedAuth> {
    let server_public = to_key(server_public)?;
    let ephemeral = StaticSecret::from(ephemeral_secret);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(server_public));

    let key = auth_key::derive(shared.as_bytes());
    let nonce = nonce::derive(&salt, &ephemeral_public);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &envelope.encode(),
                aad: &aad(&ephemeral_public, &salt),
            },
        )
        .map_err(|err| TransportError::Seal(err.to_string()))?;

    let mut session_id = salt.to_vec();
    session_id.extend_from_slice(&ciphertext);

    Ok(SealedAuth {
        ephemeral_public,
        session_id,
    })
}

pub fn aad(ephemeral_public: &[u8], salt: &Salt) -> Vec<u8> {
    let mut out = Vec::with_capacity(ephemeral_public.len() + salt.len());
    out.extend_from_slice(ephemeral_public);
    out.extend_from_slice(salt);
    out
}

fn to_key(bytes: &[u8]) -> Result<[u8; X25519_KEY_LEN]> {
    bytes.try_into().map_err(|_| TransportError::KeyLength {
        expected: X25519_KEY_LEN,
        got: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{seal, seal_with_ephemeral};
    use crate::error::TransportError;
    use crate::random::fixed_random::FixedRandom;
    use crate::reality::auth::envelope::Envelope;
    use crate::reality::auth::sealed_auth::SESSION_ID_LEN;
    use crate::reality::short_id::value::ShortId;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn envelope() -> Envelope {
        Envelope::current(1_760_000_000, ShortId::from_hex("deadbeef").unwrap()).unwrap()
    }

    fn server_public() -> [u8; 32] {
        PublicKey::from(&StaticSecret::from([0x22u8; 32])).to_bytes()
    }

    #[test]
    fn a_sealed_session_id_always_fills_the_tls_field() {
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let sealed = seal(&server_public(), &envelope(), &random).unwrap();
        assert_eq!(sealed.session_id.len(), SESSION_ID_LEN);
    }

    #[test]
    fn the_salt_is_carried_in_the_clear_at_the_front() {
        let sealed =
            seal_with_ephemeral(&server_public(), &envelope(), [0x11u8; 32], [0x99u8; 7]).unwrap();
        assert_eq!(&sealed.session_id[..7], &[0x99u8; 7]);
    }

    #[test]
    fn derives_the_ephemeral_public_key_from_the_random_source() {
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let sealed = seal(&server_public(), &envelope(), &random).unwrap();
        assert_eq!(
            sealed.ephemeral_public,
            PublicKey::from(&StaticSecret::from([0x11u8; 32])).to_bytes()
        );
    }

    #[test]
    fn a_repeated_ephemeral_key_still_yields_a_different_nonce() {
        let first =
            seal_with_ephemeral(&server_public(), &envelope(), [0x11u8; 32], [0x01u8; 7]).unwrap();
        let second =
            seal_with_ephemeral(&server_public(), &envelope(), [0x11u8; 32], [0x02u8; 7]).unwrap();
        assert_eq!(first.ephemeral_public, second.ephemeral_public);
        assert_ne!(first.session_id[7..], second.session_id[7..]);
    }

    #[test]
    fn an_explicit_ephemeral_and_salt_reproduce_the_random_path() {
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let from_random = seal(&server_public(), &envelope(), &random).unwrap();
        let explicit =
            seal_with_ephemeral(&server_public(), &envelope(), [0x11u8; 32], [0x11u8; 7]).unwrap();
        assert_eq!(from_random, explicit);
    }

    #[test]
    fn rejects_a_server_key_of_the_wrong_length() {
        assert_eq!(
            seal_with_ephemeral(&[0u8; 31], &envelope(), [0x11u8; 32], [0x01u8; 7]),
            Err(TransportError::KeyLength {
                expected: 32,
                got: 31
            })
        );
    }
}
