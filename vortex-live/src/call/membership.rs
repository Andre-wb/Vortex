use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberState {
    #[serde(rename = "invited")]
    Invited,
    #[serde(rename = "ringing")]
    Ringing,
    #[serde(rename = "connecting")]
    Connecting,
    #[serde(rename = "connected")]
    Connected,
    #[serde(rename = "left")]
    Left,
    #[serde(rename = "declined")]
    Declined,
}

impl MemberState {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberState::Invited => "invited",
            MemberState::Ringing => "ringing",
            MemberState::Connecting => "connecting",
            MemberState::Connected => "connected",
            MemberState::Left => "left",
            MemberState::Declined => "declined",
        }
    }

    pub fn on_the_call(self) -> bool {
        matches!(self, MemberState::Connecting | MemberState::Connected)
    }

    pub fn invitable_again(self) -> bool {
        matches!(self, MemberState::Left | MemberState::Declined)
    }
}

#[cfg(test)]
mod tests {
    use super::MemberState;

    #[test]
    fn only_the_connecting_and_the_connected_are_counted_as_on_the_call() {
        assert!(MemberState::Connecting.on_the_call());
        assert!(MemberState::Connected.on_the_call());
        for state in [
            MemberState::Invited,
            MemberState::Ringing,
            MemberState::Left,
            MemberState::Declined,
        ] {
            assert!(!state.on_the_call(), "{}", state.as_str());
        }
    }

    #[test]
    fn whoever_left_or_declined_may_be_invited_again() {
        assert!(MemberState::Left.invitable_again());
        assert!(MemberState::Declined.invitable_again());
        assert!(!MemberState::Connected.invitable_again());
        assert!(!MemberState::Invited.invitable_again());
    }

    #[test]
    fn a_state_survives_the_trip_back_to_the_client() {
        assert_eq!(MemberState::Invited.as_str(), "invited");
        assert_eq!(MemberState::Declined.as_str(), "declined");
    }
}
