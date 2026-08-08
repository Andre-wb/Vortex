pub const MAX_LEN: usize = 32;
pub const UNKNOWN: &str = "unknown";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Region(String);

impl Region {
    pub fn parse(value: &str) -> Option<Region> {
        if value.is_empty() || value.len() > MAX_LEN {
            return None;
        }
        if !value.bytes().all(is_allowed) {
            return None;
        }
        Some(Region(value.to_ascii_lowercase()))
    }

    pub fn unknown() -> Region {
        Region(UNKNOWN.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::{Region, MAX_LEN};

    #[test]
    fn a_country_code_is_a_region() {
        assert_eq!(Region::parse("ru").unwrap().as_str(), "ru");
        assert_eq!(Region::parse("cn-north-1").unwrap().as_str(), "cn-north-1");
        assert_eq!(Region::parse("unknown").unwrap().as_str(), "unknown");
    }

    #[test]
    fn the_same_region_written_in_two_cases_is_one_region() {
        assert_eq!(Region::parse("RU"), Region::parse("ru"));
        assert_eq!(Region::parse("Ru"), Region::parse("rU"));
    }

    #[test]
    fn a_region_is_never_a_path_a_key_or_a_sentence() {
        assert_eq!(Region::parse("../../etc"), None);
        assert_eq!(Region::parse("ru:ru"), None);
        assert_eq!(Region::parse("ru ru"), None);
        assert_eq!(Region::parse("ru\n"), None);
        assert_eq!(Region::parse("россия"), None);
        assert_eq!(Region::parse("{}"), None);
    }

    #[test]
    fn a_region_has_a_length_the_store_can_hold() {
        assert_eq!(Region::parse(""), None);
        assert!(Region::parse(&"a".repeat(MAX_LEN)).is_some());
        assert_eq!(Region::parse(&"a".repeat(MAX_LEN + 1)), None);
    }

    #[test]
    fn the_region_nobody_named_is_still_a_region() {
        assert_eq!(Region::unknown().as_str(), "unknown");
        assert_eq!(Region::parse("unknown"), Some(Region::unknown()));
    }
}
