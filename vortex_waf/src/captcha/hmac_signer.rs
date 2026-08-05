//! Подпись HMAC-SHA256.

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

    /// Ключ из общего секрета приложения — тогда любой инстанс проверит любую
    /// капчу. Если секрет пуст, берётся случайный ключ процесса: капчи
    /// перестают действовать при перезапуске и не переносятся между репликами.
    pub fn derive(app_secret: &str, domain: &str, random: &dyn RandomSource) -> Self {
        if app_secret.is_empty() {
            let mut key = vec![0u8; 32];
            random.fill_bytes(&mut key);
            return HmacSigner::new(key);
        }
        HmacSigner::new(format!("{app_secret}{domain}").into_bytes())
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
        // Сравнение в постоянном времени делает сама реализация HMAC.
        expected.len() == provided.len() && mac.verify_slice(&provided).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::HmacSigner;
    use crate::ports::signer::Signer;

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
}
