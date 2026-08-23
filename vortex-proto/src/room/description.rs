use crate::room::limits::DESCRIPTION_MAX_LEN;
use crate::room::refusal::RoomRefusal;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoomDescription(String);

impl RoomDescription {
    pub fn read(text: &str) -> Result<Self, RoomRefusal> {
        let trimmed = text.trim();
        if trimmed.chars().count() > DESCRIPTION_MAX_LEN {
            return Err(RoomRefusal::Description);
        }
        Ok(RoomDescription(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::RoomDescription;
    use crate::room::limits::DESCRIPTION_MAX_LEN;
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn an_empty_description_is_a_description() {
        assert_eq!(RoomDescription::read("").unwrap().as_str(), "");
    }

    #[test]
    fn a_description_is_kept_without_its_surrounding_whitespace() {
        assert_eq!(RoomDescription::read("  hi ").unwrap().as_str(), "hi");
    }

    #[test]
    fn a_description_longer_than_the_limit_is_refused() {
        assert!(RoomDescription::read(&"a".repeat(DESCRIPTION_MAX_LEN)).is_ok());
        assert_eq!(
            RoomDescription::read(&"a".repeat(DESCRIPTION_MAX_LEN + 1)),
            Err(RoomRefusal::Description)
        );
    }
}
