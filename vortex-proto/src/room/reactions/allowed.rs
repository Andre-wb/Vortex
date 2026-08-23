use crate::room::limits::ALLOWED_REACTIONS_MAX_LEN;
use crate::room::refusal::RoomRefusal;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllowedReactions(String);

impl AllowedReactions {
    pub fn read(text: &str) -> Result<Self, RoomRefusal> {
        if text.chars().count() > ALLOWED_REACTIONS_MAX_LEN {
            return Err(RoomRefusal::AllowedReactions);
        }
        Ok(AllowedReactions(text.to_string()))
    }

    pub fn shown(stored: Option<&str>) -> String {
        stored.unwrap_or("").to_string()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::AllowedReactions;
    use crate::room::limits::ALLOWED_REACTIONS_MAX_LEN;
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn a_list_within_the_limit_is_kept_as_written() {
        assert_eq!(AllowedReactions::read("👍,👎").unwrap().as_str(), "👍,👎");
    }

    #[test]
    fn a_list_longer_than_the_limit_is_refused() {
        assert!(AllowedReactions::read(&"a".repeat(ALLOWED_REACTIONS_MAX_LEN)).is_ok());
        assert_eq!(
            AllowedReactions::read(&"a".repeat(ALLOWED_REACTIONS_MAX_LEN + 1)),
            Err(RoomRefusal::AllowedReactions)
        );
    }

    #[test]
    fn a_room_that_allowed_nothing_shows_an_empty_list() {
        assert_eq!(AllowedReactions::shown(None), "");
        assert_eq!(AllowedReactions::shown(Some("👍")), "👍");
    }
}
