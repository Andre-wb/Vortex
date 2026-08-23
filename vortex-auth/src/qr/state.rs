use crate::account::user_id::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Confirmed(UserId),
}

impl State {
    pub fn confirmed_by(self) -> Option<UserId> {
        match self {
            State::Confirmed(user) => Some(user),
            State::Pending => None,
        }
    }

    pub fn is_pending(self) -> bool {
        matches!(self, State::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    use crate::account::user_id::UserId;

    #[test]
    fn a_pending_session_names_nobody() {
        assert!(State::Pending.is_pending());
        assert_eq!(State::Pending.confirmed_by(), None);
    }

    #[test]
    fn a_confirmed_session_names_the_account_that_confirmed_it() {
        let user = UserId::of(7).unwrap();
        assert!(!State::Confirmed(user).is_pending());
        assert_eq!(State::Confirmed(user).confirmed_by(), Some(user));
    }
}
