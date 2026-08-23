use crate::challenge::id::ChallengeId;
use crate::challenge::secret::ChallengeSecret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    id: ChallengeId,
    secret: ChallengeSecret,
    expires_in: u64,
}

impl IssuedChallenge {
    pub fn new(id: ChallengeId, secret: ChallengeSecret, expires_in: u64) -> Self {
        IssuedChallenge {
            id,
            secret,
            expires_in,
        }
    }

    pub fn id(&self) -> &ChallengeId {
        &self.id
    }

    pub fn secret(&self) -> &ChallengeSecret {
        &self.secret
    }

    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

#[cfg(test)]
mod tests {
    use super::IssuedChallenge;
    use crate::challenge::id::ChallengeId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn what_is_handed_to_the_client_is_the_identifier_the_secret_and_the_window() {
        let source = FixedEntropy::counting_from(0);
        let issued = IssuedChallenge::new(
            ChallengeId::draw(&source),
            ChallengeSecret::draw(&source),
            60,
        );
        assert_eq!(issued.id().as_str().len(), 32);
        assert_eq!(issued.secret().to_hex().len(), 64);
        assert_eq!(issued.expires_in(), 60);
    }
}
