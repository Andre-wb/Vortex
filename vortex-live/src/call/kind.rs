use serde::{Deserialize, Serialize};

pub const GROUP_AUDIO: &str = "group_audio";
pub const GROUP_VIDEO: &str = "group_video";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallKind {
    #[serde(rename = "group_audio")]
    Audio,
    #[serde(rename = "group_video")]
    Video,
}

impl CallKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            GROUP_AUDIO => Some(CallKind::Audio),
            GROUP_VIDEO => Some(CallKind::Video),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CallKind::Audio => GROUP_AUDIO,
            CallKind::Video => GROUP_VIDEO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CallKind;

    #[test]
    fn the_two_kinds_the_client_asks_for_are_read() {
        assert_eq!(CallKind::parse("group_audio"), Some(CallKind::Audio));
        assert_eq!(CallKind::parse("group_video"), Some(CallKind::Video));
    }

    #[test]
    fn a_kind_survives_the_trip_back_to_the_client() {
        assert_eq!(CallKind::Audio.as_str(), "group_audio");
        assert_eq!(CallKind::Video.as_str(), "group_video");
    }

    #[test]
    fn a_kind_nobody_defined_is_not_a_call_type() {
        assert_eq!(CallKind::parse(""), None);
        assert_eq!(CallKind::parse("audio"), None);
        assert_eq!(CallKind::parse("GROUP_AUDIO"), None);
    }
}
