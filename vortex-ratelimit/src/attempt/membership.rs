use crate::attempt::member::Member;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Membership {
    room_id: i64,
    user_id: i64,
}

impl Membership {
    pub fn of(room_id: i64, user_id: i64) -> Self {
        Membership { room_id, user_id }
    }

    pub fn member(&self) -> Member {
        Member::of_pair(self.room_id, self.user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::Membership;

    #[test]
    fn a_membership_is_counted_under_its_room_and_its_account() {
        assert_eq!(Membership::of(1, 7).member().as_str(), "1:7");
    }

    #[test]
    fn one_account_in_two_rooms_is_two_memberships() {
        assert_ne!(Membership::of(1, 7).member(), Membership::of(2, 7).member());
        assert_ne!(Membership::of(1, 7).member(), Membership::of(1, 8).member());
    }
}
