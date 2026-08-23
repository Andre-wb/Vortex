#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Complaint {
    SignedPreKeySignature,
    MissingIdentityBinding,
    IdentityBindingSignature,
    NoIdentityKey,
    MissingKyberSignature,
    KyberSignature,
}

impl Complaint {
    pub fn detail(&self) -> &'static str {
        match self {
            Complaint::SignedPreKeySignature => "Signed pre-key signature verification failed",
            Complaint::MissingIdentityBinding => "Missing identity_key_sig binding signature",
            Complaint::IdentityBindingSignature => {
                "Identity-key binding signature verification failed"
            }
            Complaint::NoIdentityKey => {
                "No Ed25519 identity key provided — signature cannot be verified"
            }
            Complaint::MissingKyberSignature => "Missing device_kyber_sig for Kyber pre-key",
            Complaint::KyberSignature => "Kyber pre-key signature verification failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Complaint;

    #[test]
    fn every_complaint_carries_its_own_wording() {
        let complaints = [
            Complaint::SignedPreKeySignature,
            Complaint::MissingIdentityBinding,
            Complaint::IdentityBindingSignature,
            Complaint::NoIdentityKey,
            Complaint::MissingKyberSignature,
            Complaint::KyberSignature,
        ];
        for (index, left) in complaints.iter().enumerate() {
            for right in complaints.iter().skip(index + 1) {
                assert_ne!(left.detail(), right.detail());
            }
        }
    }
}
