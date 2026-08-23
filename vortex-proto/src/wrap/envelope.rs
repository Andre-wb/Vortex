use crate::hex::error::HexError;
use crate::key::x25519_public::X25519Public;
use crate::wrap::ciphertext::Ciphertext;
use crate::wrap::kyber_ciphertext::KyberCiphertext;
use crate::wrap::refusal::WrapRefusal;
use crate::wrap::request::WrapRequest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WrappedKey {
    Classical {
        ephemeral_public: X25519Public,
        ciphertext: Ciphertext,
    },
    Hybrid {
        ephemeral_public: X25519Public,
        kyber_ciphertext: KyberCiphertext,
        ciphertext: Ciphertext,
    },
}

impl WrappedKey {
    pub fn parse(request: &WrapRequest) -> Result<Self, WrapRefusal> {
        let ciphertext = Ciphertext::parse_hex(&request.ciphertext)?;

        if !request.claims_hybrid() {
            let text = request
                .classical_ephemeral_text()
                .ok_or(WrapRefusal::EphemeralPublicMissing)?;
            return Ok(WrappedKey::Classical {
                ephemeral_public: ephemeral(text)?,
                ciphertext,
            });
        }

        let kyber_text = request
            .kyber_text()
            .ok_or(WrapRefusal::KyberCiphertextMissing)?;
        let ephemeral_text = request
            .hybrid_ephemeral_text()
            .ok_or(WrapRefusal::EphemeralPublicMissing)?;

        Ok(WrappedKey::Hybrid {
            ephemeral_public: ephemeral(ephemeral_text)?,
            kyber_ciphertext: KyberCiphertext::parse_hex(kyber_text)?,
            ciphertext,
        })
    }

    pub fn is_hybrid(&self) -> bool {
        matches!(self, WrappedKey::Hybrid { .. })
    }

    pub fn ephemeral_public(&self) -> &X25519Public {
        match self {
            WrappedKey::Classical {
                ephemeral_public, ..
            } => ephemeral_public,
            WrappedKey::Hybrid {
                ephemeral_public, ..
            } => ephemeral_public,
        }
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        match self {
            WrappedKey::Classical { ciphertext, .. } => ciphertext,
            WrappedKey::Hybrid { ciphertext, .. } => ciphertext,
        }
    }

    pub fn kyber_ciphertext(&self) -> Option<&KyberCiphertext> {
        match self {
            WrappedKey::Classical { .. } => None,
            WrappedKey::Hybrid {
                kyber_ciphertext, ..
            } => Some(kyber_ciphertext),
        }
    }
}

fn ephemeral(text: &str) -> Result<X25519Public, WrapRefusal> {
    X25519Public::parse_hex(text).map_err(|error| match error {
        HexError::NotHex => WrapRefusal::EphemeralPublicHex,
        HexError::Length { .. } => WrapRefusal::EphemeralPublicLength,
    })
}

#[cfg(test)]
mod tests {
    use super::WrappedKey;
    use crate::wrap::limits::KYBER_CIPHERTEXT_LEN;
    use crate::wrap::refusal::WrapRefusal;
    use crate::wrap::request::WrapRequest;

    fn ephemeral_hex() -> String {
        "1a".repeat(32)
    }

    fn ciphertext_hex() -> String {
        "2b".repeat(60)
    }

    fn kyber_hex() -> String {
        "3c".repeat(KYBER_CIPHERTEXT_LEN)
    }

    fn classical() -> WrapRequest {
        WrapRequest {
            ephemeral_pub: Some(ephemeral_hex()),
            ciphertext: ciphertext_hex(),
            ..WrapRequest::default()
        }
    }

    fn hybrid() -> WrapRequest {
        WrapRequest {
            ciphertext: ciphertext_hex(),
            hybrid: Some(true),
            x25519_ephemeral_pub: Some(ephemeral_hex()),
            kyber_ciphertext: Some(kyber_hex()),
            ..WrapRequest::default()
        }
    }

    #[test]
    fn a_classical_envelope_keeps_both_of_its_fields() {
        let parsed = WrappedKey::parse(&classical()).unwrap();
        assert!(!parsed.is_hybrid());
        assert_eq!(parsed.ephemeral_public().to_hex(), ephemeral_hex());
        assert_eq!(parsed.ciphertext().to_hex(), ciphertext_hex());
        assert!(parsed.kyber_ciphertext().is_none());
    }

    #[test]
    fn a_hybrid_envelope_keeps_all_three_of_its_fields() {
        let parsed = WrappedKey::parse(&hybrid()).unwrap();
        assert!(parsed.is_hybrid());
        assert_eq!(parsed.ephemeral_public().to_hex(), ephemeral_hex());
        assert_eq!(parsed.kyber_ciphertext().unwrap().to_hex(), kyber_hex());
    }

    #[test]
    fn a_kyber_ciphertext_without_the_flag_is_still_measured_as_hybrid() {
        let request = WrapRequest {
            ephemeral_pub: Some(ephemeral_hex()),
            ciphertext: ciphertext_hex(),
            kyber_ciphertext: Some(kyber_hex()),
            ..WrapRequest::default()
        };
        assert_eq!(
            WrappedKey::parse(&request),
            Err(WrapRefusal::EphemeralPublicMissing)
        );
    }

    #[test]
    fn a_flag_without_a_kyber_ciphertext_is_refused() {
        let request = WrapRequest {
            ciphertext: ciphertext_hex(),
            hybrid: Some(true),
            x25519_ephemeral_pub: Some(ephemeral_hex()),
            ..WrapRequest::default()
        };
        assert_eq!(
            WrappedKey::parse(&request),
            Err(WrapRefusal::KyberCiphertextMissing)
        );
    }

    #[test]
    fn a_hybrid_envelope_of_the_wrong_kyber_size_is_refused() {
        let request = WrapRequest {
            kyber_ciphertext: Some("3c".repeat(50)),
            ..hybrid()
        };
        assert_eq!(
            WrappedKey::parse(&request),
            Err(WrapRefusal::KyberCiphertextLength)
        );
    }

    #[test]
    fn a_classical_envelope_without_an_ephemeral_key_is_refused() {
        let request = WrapRequest {
            ciphertext: ciphertext_hex(),
            ..WrapRequest::default()
        };
        assert_eq!(
            WrappedKey::parse(&request),
            Err(WrapRefusal::EphemeralPublicMissing)
        );
    }

    #[test]
    fn an_ephemeral_key_padded_with_spaces_is_not_hex() {
        let request = WrapRequest {
            ephemeral_pub: Some(format!("{}  ", "1a".repeat(31))),
            ..classical()
        };
        assert_eq!(
            WrappedKey::parse(&request),
            Err(WrapRefusal::EphemeralPublicHex)
        );
    }

    #[test]
    fn an_ephemeral_key_of_the_wrong_size_is_told_apart_from_a_non_hex_one() {
        let request = WrapRequest {
            ephemeral_pub: Some("1a".repeat(31)),
            ..classical()
        };
        assert_eq!(
            WrappedKey::parse(&request),
            Err(WrapRefusal::EphemeralPublicLength)
        );
    }

    #[test]
    fn the_ciphertext_is_measured_before_the_ephemeral_key() {
        let request = WrapRequest {
            ephemeral_pub: Some("zz".repeat(32)),
            ciphertext: "aa".repeat(11),
            ..WrapRequest::default()
        };
        assert_eq!(
            WrappedKey::parse(&request),
            Err(WrapRefusal::CiphertextLength)
        );
    }
}
