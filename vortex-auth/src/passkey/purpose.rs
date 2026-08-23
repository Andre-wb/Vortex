use crate::account::user_id::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Registration(UserId),
    Login,
}

impl Purpose {
    pub fn owner(self) -> Option<UserId> {
        match self {
            Purpose::Registration(user) => Some(user),
            Purpose::Login => None,
        }
    }

    pub fn is_login(self) -> bool {
        matches!(self, Purpose::Login)
    }
}

#[cfg(test)]
mod tests {
    use super::Purpose;
    use crate::account::user_id::UserId;

    #[test]
    fn a_registration_challenge_names_the_account_that_asked_for_it() {
        let user = UserId::of(7).unwrap();
        assert_eq!(Purpose::Registration(user).owner(), Some(user));
        assert!(!Purpose::Registration(user).is_login());
    }

    #[test]
    fn a_login_challenge_belongs_to_nobody_yet() {
        assert_eq!(Purpose::Login.owner(), None);
        assert!(Purpose::Login.is_login());
    }
}
