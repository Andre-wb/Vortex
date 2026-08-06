use crate::reality::auth::envelope::Envelope;
use crate::reality::auth::salt::{Salt, SALT_LEN};
use crate::reality::auth::sealed_auth::{SESSION_ID_LEN, X25519_KEY_LEN};
use crate::reality::auth::sealer::aad;
use crate::reality::auth::{auth_key, nonce};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn open(secret: &StaticSecret, ephemeral_public: &[u8], session_id: &[u8]) -> Option<Envelope> {
    if session_id.len() != SESSION_ID_LEN {
        return None;
    }
    let ephemeral: [u8; X25519_KEY_LEN] = ephemeral_public.try_into().ok()?;
    let salt: Salt = session_id[..SALT_LEN].try_into().ok()?;
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));

    let key = auth_key::derive(shared.as_bytes());
    let nonce = nonce::derive(&salt, ephemeral_public);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &session_id[SALT_LEN..],
                aad: &aad(ephemeral_public, &salt),
            },
        )
        .ok()?;

    Envelope::decode(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::open;
    use crate::reality::auth::envelope::Envelope;
    use crate::reality::auth::sealer::seal_with_ephemeral;
    use crate::reality::short_id::value::ShortId;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn envelope() -> Envelope {
        Envelope::current(1_760_000_000, ShortId::from_hex("deadbeef").unwrap()).unwrap()
    }

    fn server() -> StaticSecret {
        StaticSecret::from([0x22u8; 32])
    }

    fn sealed(salt: [u8; 7]) -> crate::reality::auth::sealed_auth::SealedAuth {
        seal_with_ephemeral(
            PublicKey::from(&server()).as_bytes(),
            &envelope(),
            [0x11u8; 32],
            salt,
        )
        .unwrap()
    }

    #[test]
    fn opens_what_the_sealer_produced() {
        let sealed = sealed([0x01; 7]);
        assert_eq!(
            open(&server(), &sealed.ephemeral_public, &sealed.session_id),
            Some(envelope())
        );
    }

    #[test]
    fn opens_regardless_of_the_salt_chosen() {
        let sealed = sealed([0xFE; 7]);
        assert_eq!(
            open(&server(), &sealed.ephemeral_public, &sealed.session_id),
            Some(envelope())
        );
    }

    #[test]
    fn another_server_key_cannot_open_it() {
        let sealed = sealed([0x01; 7]);
        let stranger = StaticSecret::from([0x33u8; 32]);
        assert_eq!(
            open(&stranger, &sealed.ephemeral_public, &sealed.session_id),
            None
        );
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let sealed = sealed([0x01; 7]);
        let mut broken = sealed.session_id.clone();
        broken[10] ^= 0x01;
        assert_eq!(open(&server(), &sealed.ephemeral_public, &broken), None);
    }

    #[test]
    fn a_tampered_salt_is_rejected() {
        let sealed = sealed([0x01; 7]);
        let mut broken = sealed.session_id.clone();
        broken[0] ^= 0x01;
        assert_eq!(open(&server(), &sealed.ephemeral_public, &broken), None);
    }

    #[test]
    fn a_session_id_of_the_wrong_length_is_rejected() {
        let sealed = sealed([0x01; 7]);
        assert_eq!(
            open(
                &server(),
                &sealed.ephemeral_public,
                &sealed.session_id[..31]
            ),
            None
        );
    }

    #[test]
    fn an_ephemeral_key_of_the_wrong_length_is_rejected() {
        assert_eq!(open(&server(), &[0u8; 31], &[0u8; 32]), None);
    }
}
