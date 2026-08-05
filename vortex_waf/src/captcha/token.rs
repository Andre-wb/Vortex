//! Формат идентификатора капчи: `<случайный hex>.<срок>:<подпись>`.
//!
//! Состояние на сервере не хранится: срок и подпись ответа лежат прямо в
//! идентификаторе, поэтому любая реплика проверит любую капчу.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptchaToken {
    pub nonce: String,
    pub expires_at: i64,
    pub signature: String,
}

impl CaptchaToken {
    pub fn new(nonce: impl Into<String>, expires_at: i64, signature: impl Into<String>) -> Self {
        CaptchaToken {
            nonce: nonce.into(),
            expires_at,
            signature: signature.into(),
        }
    }

    pub fn encode(&self) -> String {
        format!("{}.{}:{}", self.nonce, self.expires_at, self.signature)
    }

    pub fn decode(raw: &str) -> Option<CaptchaToken> {
        let (nonce, rest) = raw.split_once('.')?;
        let (expires, signature) = rest.split_once(':')?;
        Some(CaptchaToken::new(nonce, expires.parse().ok()?, signature))
    }

    /// Данные, которые подписываются: ответ и срок действия.
    pub fn payload(answer: &str, expires_at: i64) -> String {
        format!("{}:{}", answer.trim(), expires_at)
    }
}

#[cfg(test)]
mod tests {
    use super::CaptchaToken;

    #[test]
    fn encode_decode_round_trip() {
        let token = CaptchaToken::new("aabb", 1_700_000_000, "deadbeef");
        let decoded = CaptchaToken::decode(&token.encode()).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(CaptchaToken::decode("без-точки").is_none());
        assert!(CaptchaToken::decode("nonce.без-двоеточия").is_none());
        assert!(CaptchaToken::decode("nonce.не-число:sig").is_none());
    }

    #[test]
    fn payload_trims_the_answer() {
        assert_eq!(CaptchaToken::payload("  7 ", 10), "7:10");
    }
}
