use crate::error::{Result, TransportError};
use crate::ports::random_source::RandomSource;
use crate::reality::auth::envelope::Envelope;
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
    seal_with_ephemeral(server_public, envelope, secret_bytes)
}

pub fn seal_with_ephemeral(
    server_public: &[u8],
    envelope: &Envelope,
    ephemeral_secret: [u8; X25519_KEY_LEN],
) -> Result<SealedAuth> {
    let server_public = to_key(server_public)?;
    let ephemeral = StaticSecret::from(ephemeral_secret);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(server_public));

    let key = auth_key::derive(shared.as_bytes());
    let nonce = nonce::for_ephemeral(&ephemeral_public);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key));
    let session_id = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &envelope.encode(),
                aad: &ephemeral_public,
            },
        )
        .map_err(|err| TransportError::Seal(err.to_string()))?;

    Ok(SealedAuth {
        ephemeral_public,
        session_id,
    })
}

fn to_key(bytes: &[u8]) -> Result<[u8; X25519_KEY_LEN]> {
    bytes.try_into().map_err(|_| TransportError::KeyLength {
        expected: X25519_KEY_LEN,
        got: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::seal;
    use crate::error::TransportError;
    use crate::random::fixed_random::FixedRandom;
    use crate::reality::auth::envelope::Envelope;
    use crate::reality::short_id::value::ShortId;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn envelope() -> Envelope {
        Envelope::current(1_760_000_000, ShortId::from_hex("deadbeef").unwrap())
    }

    #[test]
    fn derives_the_ephemeral_public_key_from_the_random_source() {
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let server = StaticSecret::from([0x22u8; 32]);
        let sealed = seal(PublicKey::from(&server).as_bytes(), &envelope(), &random).unwrap();
        let expected = PublicKey::from(&StaticSecret::from([0x11u8; 32])).to_bytes();
        assert_eq!(sealed.ephemeral_public, expected);
    }

    #[test]
    fn session_id_carries_the_gcm_tag() {
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let server = StaticSecret::from([0x22u8; 32]);
        let sealed = seal(PublicKey::from(&server).as_bytes(), &envelope(), &random).unwrap();
        assert_eq!(sealed.session_id.len(), envelope().encode().len() + 16);
    }

    #[test]
    fn an_explicit_ephemeral_reproduces_the_random_path() {
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let server = StaticSecret::from([0x22u8; 32]);
        let server_public = PublicKey::from(&server).to_bytes();

        let from_random = seal(&server_public, &envelope(), &random).unwrap();
        let explicit =
            super::seal_with_ephemeral(&server_public, &envelope(), [0x11u8; 32]).unwrap();
        assert_eq!(from_random, explicit);
    }

    #[test]
    fn rejects_a_server_key_of_the_wrong_length() {
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        assert_eq!(
            seal(&[0u8; 31], &envelope(), &random),
            Err(TransportError::KeyLength {
                expected: 32,
                got: 31
            })
        );
    }
}
