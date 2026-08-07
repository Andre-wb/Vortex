use crate::captcha::signing_key;
use crate::ports::random_source::RandomSource;
use crate::ports::signer::Signer;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct HmacSigner {
    secret: Vec<u8>,
}

impl HmacSigner {
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        HmacSigner {
            secret: secret.as_ref().to_vec(),
        }
    }

    pub fn derive(app_secret: &str, domain: &str, random: &dyn RandomSource) -> Self {
        if app_secret.is_empty() {
            return HmacSigner::new(signing_key::random(random));
        }
        HmacSigner::new(signing_key::derive(app_secret, domain))
    }
}

impl Signer for HmacSigner {
    fn sign(&self, payload: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC принимает любой ключ");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn verify(&self, payload: &str, signature: &str) -> bool {
        let Ok(expected) = hex::decode(self.sign(payload)) else {
            return false;
        };
        let Ok(provided) = hex::decode(signature) else {
            return false;
        };
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC принимает любой ключ");
        mac.update(payload.as_bytes());
        expected.len() == provided.len() && mac.verify_slice(&provided).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::HmacSigner;
    use crate::ports::signer::Signer;
    use crate::random::sequence_random::SequenceRandom;

    #[test]
    fn signature_round_trips() {
        let signer = HmacSigner::new("секрет");
        let sig = signer.sign("7:1000");
        assert!(signer.verify("7:1000", &sig));
        assert!(!signer.verify("8:1000", &sig));
    }

    #[test]
    fn malformed_signature_is_rejected() {
        let signer = HmacSigner::new("секрет");
        assert!(!signer.verify("7:1000", "не-хекс"));
        assert!(!signer.verify("7:1000", "ab"));
    }

    #[test]
    fn different_secrets_do_not_cross_verify() {
        let a = HmacSigner::new("ключ-А");
        let b = HmacSigner::new("ключ-Б");
        assert!(!b.verify("payload", &a.sign("payload")));
    }

    #[test]
    fn derivation_from_one_secret_is_reproducible() {
        let random = SequenceRandom::new(vec![]).with_filler(0x11);
        let a = HmacSigner::derive("секрет", "waf-captcha-v1", &random);
        let b = HmacSigner::derive("секрет", "waf-captcha-v1", &random);
        assert!(b.verify("7:1000", &a.sign("7:1000")));
    }

    #[test]
    fn derived_keys_of_different_domains_do_not_cross_verify() {
        let random = SequenceRandom::new(vec![]).with_filler(0x11);
        let captcha = HmacSigner::derive("секрет", "waf-captcha-v1", &random);
        let other = HmacSigner::derive("секрет", "waf-other-v1", &random);
        assert!(!other.verify("7:1000", &captcha.sign("7:1000")));
    }

    #[test]
    fn an_empty_secret_falls_back_to_a_random_key() {
        let first = HmacSigner::derive("", "waf-captcha-v1", &SequenceRandom::new(vec![]));
        let second = HmacSigner::derive(
            "",
            "waf-captcha-v1",
            &SequenceRandom::new(vec![]).with_filler(0x11),
        );
        assert!(!second.verify("7:1000", &first.sign("7:1000")));
    }
}
