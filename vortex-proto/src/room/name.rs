use crate::room::limits::{NAME_MAX_LEN, NAME_MIN_LEN};
use crate::room::refusal::RoomRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomName(String);

impl RoomName {
    pub fn read(text: &str) -> Result<Self, RoomRefusal> {
        let trimmed = text.trim();
        let written = trimmed.chars().count();
        if !(NAME_MIN_LEN..=NAME_MAX_LEN).contains(&written) {
            return Err(RoomRefusal::Name);
        }
        Ok(RoomName(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::RoomName;
    use crate::room::limits::NAME_MAX_LEN;
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn a_name_is_kept_without_its_surrounding_whitespace() {
        assert_eq!(RoomName::read("  General  ").unwrap().as_str(), "General");
    }

    #[test]
    fn a_name_of_nothing_but_whitespace_is_no_name() {
        assert_eq!(RoomName::read("   "), Err(RoomRefusal::Name));
        assert_eq!(RoomName::read(""), Err(RoomRefusal::Name));
    }

    #[test]
    fn a_name_longer_than_the_limit_is_refused_rather_than_cut() {
        assert!(RoomName::read(&"a".repeat(NAME_MAX_LEN)).is_ok());
        assert_eq!(
            RoomName::read(&"a".repeat(NAME_MAX_LEN + 1)),
            Err(RoomRefusal::Name)
        );
    }

    #[test]
    fn a_name_is_measured_in_characters_and_not_in_bytes() {
        assert!(RoomName::read(&"ё".repeat(NAME_MAX_LEN)).is_ok());
        assert_eq!(
            RoomName::read(&"ё".repeat(NAME_MAX_LEN + 1)),
            Err(RoomRefusal::Name)
        );
    }
}
