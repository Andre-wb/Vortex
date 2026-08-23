use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountClaim {
    Missing,
    Mismatch,
    Taken {
        secret: ChallengeSecret,
        user: UserId,
    },
}

impl AccountClaim {
    pub fn outcome(&self) -> &'static str {
        match self {
            AccountClaim::Missing => "missing",
            AccountClaim::Mismatch => "mismatch",
            AccountClaim::Taken { .. } => "taken",
        }
    }

    pub fn secret(&self) -> Option<&ChallengeSecret> {
        match self {
            AccountClaim::Taken { secret, .. } => Some(secret),
            _ => None,
        }
    }

    pub fn user(&self) -> Option<UserId> {
        match self {
            AccountClaim::Taken { user, .. } => Some(*user),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionClaim {
    Missing,
    Mismatch,
    Taken(ChallengeSecret),
}

impl SessionClaim {
    pub fn outcome(&self) -> &'static str {
        match self {
            SessionClaim::Missing => "missing",
            SessionClaim::Mismatch => "mismatch",
            SessionClaim::Taken(_) => "taken",
        }
    }

    pub fn secret(&self) -> Option<&ChallengeSecret> {
        match self {
            SessionClaim::Taken(secret) => Some(secret),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountClaim, SessionClaim};
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::random::fixed_entropy::FixedEntropy;

    fn secret() -> ChallengeSecret {
        ChallengeSecret::draw(&FixedEntropy::counting_from(0))
    }

    #[test]
    fn only_a_taken_challenge_names_the_account_and_hands_out_the_secret() {
        let taken = AccountClaim::Taken {
            secret: secret(),
            user: UserId::of(7).unwrap(),
        };
        assert_eq!(taken.user(), Some(UserId::of(7).unwrap()));
        assert!(taken.secret().is_some());
        assert!(AccountClaim::Missing.user().is_none());
        assert!(AccountClaim::Mismatch.secret().is_none());
    }

    #[test]
    fn a_session_claim_hands_out_the_secret_only_when_it_was_taken() {
        assert!(SessionClaim::Taken(secret()).secret().is_some());
        assert!(SessionClaim::Missing.secret().is_none());
        assert_eq!(SessionClaim::Mismatch.outcome(), "mismatch");
    }
}
