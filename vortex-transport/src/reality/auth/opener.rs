use crate::reality::auth::envelope::Envelope;
use crate::reality::auth::sealed_auth::X25519_KEY_LEN;
use crate::reality::auth::{auth_key, nonce};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn open(secret: &StaticSecret, ephemeral_public: &[u8], session_id: &[u8]) -> Option<Envelope> {
    let ephemeral: [u8; X25519_KEY_LEN] = ephemeral_public.try_into().ok()?;
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));

    let key = auth_key::derive(shared.as_bytes());
    let nonce = nonce::for_ephemeral(ephemeral_public);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: session_id,
                aad: ephemeral_public,
            },
        )
        .ok()?;

    Envelope::decode(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::open;
    use crate::random::fixed_random::FixedRandom;
    use crate::reality::auth::envelope::Envelope;
    use crate::reality::auth::sealer::seal;
    use crate::reality::short_id::value::ShortId;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn envelope() -> Envelope {
        Envelope::current(1_760_000_000, ShortId::from_hex("deadbeef").unwrap())
    }

    #[test]
    fn opens_what_the_sealer_produced() {
        let server = StaticSecret::from([0x22u8; 32]);
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let sealed = seal(PublicKey::from(&server).as_bytes(), &envelope(), &random).unwrap();

        let opened = open(&server, &sealed.ephemeral_public, &sealed.session_id);
        assert_eq!(opened, Some(envelope()));
    }

    #[test]
    fn another_server_key_cannot_open_it() {
        let server = StaticSecret::from([0x22u8; 32]);
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let sealed = seal(PublicKey::from(&server).as_bytes(), &envelope(), &random).unwrap();

        let stranger = StaticSecret::from([0x33u8; 32]);
        assert_eq!(
            open(&stranger, &sealed.ephemeral_public, &sealed.session_id),
            None
        );
    }

    #[test]
    fn a_tampered_session_id_is_rejected() {
        let server = StaticSecret::from([0x22u8; 32]);
        let random = FixedRandom::new(vec![]).with_filler(0x11);
        let sealed = seal(PublicKey::from(&server).as_bytes(), &envelope(), &random).unwrap();

        let mut broken = sealed.session_id.clone();
        broken[0] ^= 0x01;
        assert_eq!(open(&server, &sealed.ephemeral_public, &broken), None);
    }

    #[test]
    fn an_ephemeral_key_of_the_wrong_length_is_rejected() {
        let server = StaticSecret::from([0x22u8; 32]);
        assert_eq!(open(&server, &[0u8; 31], &[0u8; 25]), None);
    }
}
