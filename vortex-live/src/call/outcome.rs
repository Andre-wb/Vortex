use crate::call::record::Call;

#[derive(Debug, Clone, PartialEq)]
pub enum Started {
    Fresh(Call),
    Already(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Joined {
    Joined(Call),
    NotInvited,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Declined {
    Declined,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Left {
    Left { call: Call, ended: bool },
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Added {
    Added(Call),
    NotAParticipant,
    AlreadyIn,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Ended {
    Ended(Call),
    NotInitiator,
    Missing,
}

#[cfg(test)]
mod tests {
    use super::{Ended, Joined, Left, Started};
    use crate::call::record::tests::call;

    #[test]
    fn a_fresh_call_is_told_apart_from_one_the_room_already_has() {
        assert_ne!(Started::Fresh(call()), Started::Already("abcd".to_owned()));
    }

    #[test]
    fn a_call_that_is_gone_is_told_apart_from_one_the_caller_may_not_join() {
        assert_ne!(Joined::Missing, Joined::NotInvited);
    }

    #[test]
    fn leaving_says_whether_the_call_ended_with_it() {
        let left = Left::Left {
            call: call(),
            ended: true,
        };
        assert_ne!(
            left,
            Left::Left {
                call: call(),
                ended: false
            }
        );
    }

    #[test]
    fn only_the_initiator_ends_the_call_for_everyone() {
        assert_ne!(Ended::Ended(call()), Ended::NotInitiator);
    }
}
