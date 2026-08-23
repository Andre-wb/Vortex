use crate::stream::donation::Donation;
use crate::stream::participant::StreamParticipant;
use crate::stream::view::Snapshot;

#[derive(Debug, Clone, PartialEq)]
pub enum Opened {
    Fresh(Box<Snapshot>),
    AlreadyLive,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stopped {
    Stopped { peak: u64 },
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Seated {
    Fresh(Box<Snapshot>),
    Already(Box<Snapshot>),
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Unseated {
    Left { host_left: bool },
    NotIn,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Hand {
    Raised,
    AutoAccepted(Box<StreamParticipant>),
    Lowered,
    AlreadySpeaks,
    NotIn,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Granted {
    Granted(Box<StreamParticipant>),
    NotAllowed,
    NoSuchParticipant,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kicked {
    Kicked,
    NotAllowed,
    NoSuchParticipant,
    CannotKickHost,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Reacted {
    Counted(String),
    Disabled,
    NotIn,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Donated {
    Donated(Box<Donation>),
    Disabled,
    NotIn,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Updated {
    Updated(Box<Snapshot>),
    NotAllowed,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Amended {
    Amended(Box<StreamParticipant>),
    NotAllowed,
    Missing,
}

#[cfg(test)]
mod tests {
    use super::{Granted, Hand, Kicked, Reacted, Stopped, Unseated};

    #[test]
    fn a_stream_that_is_gone_is_told_apart_from_a_viewer_who_is_not_in_it() {
        assert_ne!(Unseated::Missing, Unseated::NotIn);
        assert_ne!(Reacted::Missing, Reacted::NotIn);
    }

    #[test]
    fn a_hand_that_was_accepted_at_once_is_told_apart_from_one_that_waits() {
        assert_ne!(Hand::Raised, Hand::Lowered);
        assert_ne!(Hand::AlreadySpeaks, Hand::NotIn);
    }

    #[test]
    fn a_refusal_by_right_is_told_apart_from_a_missing_participant() {
        assert_ne!(Granted::NotAllowed, Granted::NoSuchParticipant);
        assert_ne!(Kicked::CannotKickHost, Kicked::NotAllowed);
    }

    #[test]
    fn stopping_a_stream_reports_the_peak_it_reached() {
        assert_ne!(Stopped::Stopped { peak: 5 }, Stopped::Stopped { peak: 6 });
    }
}
