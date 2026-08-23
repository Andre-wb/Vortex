use crate::hex::decode::decode;
use crate::hex::encode::encode;
use crate::wrap::limits::KYBER_CIPHERTEXT_LEN;
use crate::wrap::refusal::WrapRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberCiphertext(Vec<u8>);

impl KyberCiphertext {
    pub fn parse_hex(text: &str) -> Result<Self, WrapRefusal> {
        let bytes = decode(text).map_err(|_| WrapRefusal::KyberCiphertextHex)?;
        if bytes.len() != KYBER_CIPHERTEXT_LEN {
            return Err(WrapRefusal::KyberCiphertextLength);
        }
        Ok(KyberCiphertext(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        encode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::KyberCiphertext;
    use crate::wrap::limits::KYBER_CIPHERTEXT_LEN;
    use crate::wrap::refusal::WrapRefusal;

    #[test]
    fn an_ml_kem_768_ciphertext_survives_a_round_trip() {
        let text = "5c".repeat(KYBER_CIPHERTEXT_LEN);
        assert_eq!(KyberCiphertext::parse_hex(&text).unwrap().to_hex(), text);
    }

    #[test]
    fn a_shorter_ciphertext_is_refused() {
        assert_eq!(
            KyberCiphertext::parse_hex(&"5c".repeat(50)),
            Err(WrapRefusal::KyberCiphertextLength)
        );
    }

    #[test]
    fn a_longer_ciphertext_is_refused() {
        assert_eq!(
            KyberCiphertext::parse_hex(&"5c".repeat(KYBER_CIPHERTEXT_LEN + 1)),
            Err(WrapRefusal::KyberCiphertextLength)
        );
    }

    #[test]
    fn a_non_hex_ciphertext_is_refused_before_length() {
        assert_eq!(
            KyberCiphertext::parse_hex("zz"),
            Err(WrapRefusal::KyberCiphertextHex)
        );
    }
}
