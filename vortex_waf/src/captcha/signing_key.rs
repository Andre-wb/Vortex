use crate::ports::random_source::RandomSource;
use hkdf::Hkdf;
use sha2::Sha256;

pub const KEY_LEN: usize = 32;

pub fn derive(app_secret: &str, domain: &str) -> [u8; KEY_LEN] {
    let hkdf = Hkdf::<Sha256>::new(None, app_secret.as_bytes());
    let mut key = [0u8; KEY_LEN];
    hkdf.expand(domain.as_bytes(), &mut key)
        .expect("32 байта всегда помещаются в вывод HKDF-SHA256");
    key
}

pub fn random(source: &dyn RandomSource) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    source.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::{derive, random, KEY_LEN};
    use crate::random::sequence_random::SequenceRandom;

    #[test]
    fn derivation_is_frozen() {
        assert_eq!(
            hex::encode(derive("секрет", "waf-captcha-v1")),
            "d5f7cc7dce083bd34bef3113c3ef88fc626d37db4f6069de56fe1b3437e03482"
        );
    }

    #[test]
    fn the_domain_separates_keys_of_one_secret() {
        assert_ne!(
            derive("секрет", "waf-captcha-v1"),
            derive("секрет", "waf-captcha-v2")
        );
    }

    #[test]
    fn different_secrets_give_different_keys() {
        assert_ne!(
            derive("ключ-А", "waf-captcha-v1"),
            derive("ключ-Б", "waf-captcha-v1")
        );
    }

    #[test]
    fn a_moved_boundary_between_secret_and_domain_changes_the_key() {
        assert_ne!(derive("ab", "cd"), derive("a", "bcd"));
    }

    #[test]
    fn a_random_key_fills_the_whole_length() {
        let key = random(&SequenceRandom::new(vec![]).with_filler(0x11));
        assert_eq!(key, [0x11u8; KEY_LEN]);
    }
}
