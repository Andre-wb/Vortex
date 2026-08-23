#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapRefusal {
    EphemeralPublicMissing,
    EphemeralPublicHex,
    EphemeralPublicLength,
    CiphertextHex,
    CiphertextLength,
    KyberCiphertextMissing,
    KyberCiphertextHex,
    KyberCiphertextLength,
}

impl WrapRefusal {
    pub fn reason(&self) -> &'static str {
        match self {
            WrapRefusal::EphemeralPublicMissing => "ephemeral_public_missing",
            WrapRefusal::EphemeralPublicHex => "ephemeral_public_hex",
            WrapRefusal::EphemeralPublicLength => "ephemeral_public_length",
            WrapRefusal::CiphertextHex => "ciphertext_hex",
            WrapRefusal::CiphertextLength => "ciphertext_length",
            WrapRefusal::KyberCiphertextMissing => "kyber_ciphertext_missing",
            WrapRefusal::KyberCiphertextHex => "kyber_ciphertext_hex",
            WrapRefusal::KyberCiphertextLength => "kyber_ciphertext_length",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WrapRefusal;

    #[test]
    fn every_refusal_names_itself() {
        for refusal in [
            WrapRefusal::EphemeralPublicMissing,
            WrapRefusal::EphemeralPublicHex,
            WrapRefusal::EphemeralPublicLength,
            WrapRefusal::CiphertextHex,
            WrapRefusal::CiphertextLength,
            WrapRefusal::KyberCiphertextMissing,
            WrapRefusal::KyberCiphertextHex,
            WrapRefusal::KyberCiphertextLength,
        ] {
            assert!(!refusal.reason().is_empty());
        }
    }

    #[test]
    fn a_missing_key_is_told_apart_from_a_malformed_one() {
        assert_ne!(
            WrapRefusal::EphemeralPublicMissing.reason(),
            WrapRefusal::EphemeralPublicHex.reason()
        );
    }
}
