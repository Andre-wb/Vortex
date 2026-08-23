use crate::account::user_id::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handover {
    Missing,
    Pending,
    Taken(UserId),
}

impl Handover {
    pub fn outcome(self) -> &'static str {
        match self {
            Handover::Missing => "missing",
            Handover::Pending => "pending",
            Handover::Taken(_) => "taken",
        }
    }

    pub fn user(self) -> Option<UserId> {
        match self {
            Handover::Taken(user) => Some(user),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Handover;
    use crate::account::user_id::UserId;

    #[test]
    fn only_a_taken_session_names_the_account_the_desktop_gets() {
        let user = UserId::of(7).unwrap();
        assert_eq!(Handover::Taken(user).user(), Some(user));
        assert_eq!(Handover::Pending.user(), None);
        assert_eq!(Handover::Missing.user(), None);
    }

    #[test]
    fn every_outcome_names_itself_for_the_caller() {
        assert_eq!(Handover::Missing.outcome(), "missing");
        assert_eq!(Handover::Pending.outcome(), "pending");
        assert_eq!(Handover::Taken(UserId::of(1).unwrap()).outcome(), "taken");
    }
}
