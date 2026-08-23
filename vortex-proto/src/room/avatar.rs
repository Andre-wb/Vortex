use crate::room::limits::{AVATAR_MAX_LEN, DEFAULT_AVATAR, VOICE_AVATAR};
use crate::room::refusal::RoomRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomAvatar(String);

impl RoomAvatar {
    pub fn read(text: &str) -> Result<Self, RoomRefusal> {
        if text.chars().count() > AVATAR_MAX_LEN {
            return Err(RoomRefusal::Avatar);
        }
        Ok(RoomAvatar(text.to_string()))
    }

    pub fn given(is_voice: bool) -> Self {
        RoomAvatar(if is_voice {
            VOICE_AVATAR.to_string()
        } else {
            DEFAULT_AVATAR.to_string()
        })
    }

    pub fn shown(stored: Option<&str>) -> String {
        stored
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_AVATAR)
            .to_string()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::RoomAvatar;
    use crate::room::limits::{AVATAR_MAX_LEN, DEFAULT_AVATAR, VOICE_AVATAR};
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn an_avatar_keeps_its_whitespace_and_is_only_measured() {
        assert_eq!(RoomAvatar::read(" a ").unwrap().as_str(), " a ");
        assert!(RoomAvatar::read(&"a".repeat(AVATAR_MAX_LEN)).is_ok());
        assert_eq!(
            RoomAvatar::read(&"a".repeat(AVATAR_MAX_LEN + 1)),
            Err(RoomRefusal::Avatar)
        );
    }

    #[test]
    fn a_voice_room_is_born_with_a_different_avatar() {
        assert_eq!(RoomAvatar::given(true).as_str(), VOICE_AVATAR);
        assert_eq!(RoomAvatar::given(false).as_str(), DEFAULT_AVATAR);
    }

    #[test]
    fn a_room_without_an_avatar_is_shown_with_the_default_one() {
        assert_eq!(RoomAvatar::shown(None), DEFAULT_AVATAR);
        assert_eq!(RoomAvatar::shown(Some("")), DEFAULT_AVATAR);
        assert_eq!(RoomAvatar::shown(Some("🎧")), "🎧");
    }
}
