use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::wallet::message::LinkMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    message: LinkMessage,
    expires_at: i64,
    ttl_seconds: u64,
}

impl IssuedChallenge {
    pub fn new(message: LinkMessage, expires_at: i64, ttl_seconds: u64) -> Self {
        IssuedChallenge {
            message,
            expires_at,
            ttl_seconds,
        }
    }

    pub fn rendered(&self) -> String {
        STANDARD.encode(self.message.as_bytes())
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    use super::IssuedChallenge;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::random::fixed_entropy::FixedEntropy;
    use crate::wallet::message::LinkMessage;

    #[test]
    fn the_client_is_handed_the_exact_bytes_its_wallet_must_sign() {
        let secret = ChallengeSecret::draw(&FixedEntropy::counting_from(0));
        let message = LinkMessage::of(UserId::of(7).unwrap(), &secret);
        let issued = IssuedChallenge::new(message.clone(), 1_300, 300);

        assert_eq!(
            STANDARD.decode(issued.rendered()).unwrap(),
            message.as_bytes()
        );
        assert_eq!(issued.expires_at(), 1_300);
        assert_eq!(issued.ttl_seconds(), 300);
    }
}
