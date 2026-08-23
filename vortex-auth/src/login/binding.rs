use crate::account::user_id::UserId;
use crate::login::key::LoginPublicKey;
use crate::qr::session_id::QrSessionId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    Account {
        user: UserId,
        pubkey: LoginPublicKey,
    },
    QrSession(QrSessionId),
    Decoy,
}

impl Binding {
    pub fn account(&self) -> Option<UserId> {
        match self {
            Binding::Account { user, .. } => Some(*user),
            _ => None,
        }
    }

    pub fn is_decoy(&self) -> bool {
        matches!(self, Binding::Decoy)
    }

    pub fn answers_key(&self, supplied: &str) -> bool {
        match self {
            Binding::Account { pubkey, .. } => pubkey.matches(supplied),
            _ => false,
        }
    }

    pub fn answers_session(&self, session: &QrSessionId) -> bool {
        match self {
            Binding::QrSession(bound) => bound == session,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Binding;
    use crate::account::user_id::UserId;
    use crate::login::key::LoginPublicKey;
    use crate::qr::session_id::QrSessionId;

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn account() -> Binding {
        Binding::Account {
            user: UserId::of(7).unwrap(),
            pubkey: LoginPublicKey::parse(KEY).unwrap(),
        }
    }

    #[test]
    fn a_challenge_bound_to_an_account_answers_only_that_accounts_key() {
        assert_eq!(account().account(), Some(UserId::of(7).unwrap()));
        assert!(account().answers_key(KEY));
        assert!(!account().answers_key(&KEY.replace('0', "1")));
    }

    #[test]
    fn a_challenge_bound_to_a_qr_session_never_answers_a_key() {
        let bound = Binding::QrSession(QrSessionId::parse("abcd").unwrap());
        assert!(!bound.answers_key(KEY));
        assert_eq!(bound.account(), None);
        assert!(bound.answers_session(&QrSessionId::parse("abcd").unwrap()));
        assert!(!bound.answers_session(&QrSessionId::parse("dcba").unwrap()));
    }

    #[test]
    fn a_decoy_answers_nothing_at_all() {
        assert!(Binding::Decoy.is_decoy());
        assert!(!Binding::Decoy.answers_key(KEY));
        assert!(!Binding::Decoy.answers_session(&QrSessionId::parse("abcd").unwrap()));
        assert_eq!(Binding::Decoy.account(), None);
    }

    #[test]
    fn only_a_decoy_is_a_decoy() {
        assert!(!account().is_decoy());
        assert!(!Binding::QrSession(QrSessionId::parse("abcd").unwrap()).is_decoy());
    }
}
