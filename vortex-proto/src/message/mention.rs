use crate::message::limits::{MENTION_MAX_LEN, MENTION_MIN_LEN};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mention(String);

impl Mention {
    pub fn read(text: &str) -> Option<Self> {
        let written = text.chars().count();
        if !(MENTION_MIN_LEN..=MENTION_MAX_LEN).contains(&written) {
            return None;
        }
        Some(Mention(text.to_lowercase().trim().to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Mention;

    #[test]
    fn a_username_is_read_in_lower_case() {
        assert_eq!(Mention::read("Alice").unwrap().as_str(), "alice");
        assert_eq!(Mention::read("БОРИС").unwrap().as_str(), "борис");
    }

    #[test]
    fn surrounding_whitespace_is_stripped_after_the_length_is_measured() {
        assert_eq!(Mention::read(" ab ").unwrap().as_str(), "ab");
        assert_eq!(Mention::read("  a  ").unwrap().as_str(), "a");
    }

    #[test]
    fn a_name_shorter_than_three_characters_is_not_a_mention() {
        assert_eq!(Mention::read(""), None);
        assert_eq!(Mention::read("ab"), None);
    }

    #[test]
    fn a_name_longer_than_thirty_characters_is_not_a_mention() {
        assert_eq!(Mention::read(&"a".repeat(31)), None);
        assert!(Mention::read(&"a".repeat(30)).is_some());
    }

    #[test]
    fn length_is_counted_in_characters_and_not_in_bytes() {
        assert!(Mention::read("ёжи").is_some());
        assert_eq!(Mention::read(&"ё".repeat(31)), None);
    }
}
