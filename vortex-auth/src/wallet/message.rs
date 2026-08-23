use subtle::ConstantTimeEq;

use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;

pub const PREFIX: &[u8] = b"vortex:link-wallet:v1:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMessage(Vec<u8>);

impl LinkMessage {
    pub fn of(user: UserId, secret: &ChallengeSecret) -> Self {
        let account = user.value().to_string();
        let mut bytes =
            Vec::with_capacity(PREFIX.len() + account.len() + 1 + secret.as_bytes().len());
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(account.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(secret.as_bytes());
        LinkMessage(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn matches(&self, supplied: &[u8]) -> bool {
        if self.0.len() != supplied.len() {
            return false;
        }
        bool::from(self.0.ct_eq(supplied))
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkMessage, PREFIX};
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::random::fixed_entropy::FixedEntropy;

    fn secret() -> ChallengeSecret {
        ChallengeSecret::draw(&FixedEntropy::counting_from(0))
    }

    #[test]
    fn the_signed_bytes_name_the_application_and_the_account() {
        let message = LinkMessage::of(UserId::of(42).unwrap(), &secret());
        assert!(message.as_bytes().starts_with(PREFIX));
        assert_eq!(&message.as_bytes()[PREFIX.len()..PREFIX.len() + 3], b"42:");
        assert_eq!(message.as_bytes().len(), PREFIX.len() + 3 + 32);
    }

    #[test]
    fn a_signature_gathered_for_one_account_does_not_fit_another() {
        let shared = secret();
        let mine = LinkMessage::of(UserId::of(1).unwrap(), &shared);
        let theirs = LinkMessage::of(UserId::of(2).unwrap(), &shared);
        assert!(!mine.matches(theirs.as_bytes()));
    }

    #[test]
    fn the_message_the_client_returns_must_be_the_one_it_was_handed() {
        let message = LinkMessage::of(UserId::of(7).unwrap(), &secret());
        assert!(message.matches(message.as_bytes()));
        assert!(!message.matches(b"vortex:link-wallet:v1:7:"));
        assert!(!message.matches(&[]));
    }
}
