use crate::message::limits::MAX_MENTIONS;
use crate::message::mention::Mention;
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mentions(Vec<Mention>);

impl Mentions {
    pub fn read(value: Option<&Value>) -> Self {
        let Some(Value::Array(entries)) = value else {
            return Mentions(Vec::new());
        };
        let kept = entries
            .iter()
            .take(MAX_MENTIONS)
            .filter_map(|entry| entry.as_str())
            .filter_map(Mention::read)
            .collect();
        Mentions(kept)
    }

    pub fn names(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|mention| mention.as_str().to_string())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::Mentions;
    use crate::message::limits::MAX_MENTIONS;
    use serde_json::json;

    fn read(value: serde_json::Value) -> Vec<String> {
        Mentions::read(Some(&value)).names()
    }

    #[test]
    fn every_usable_name_is_kept_in_lower_case() {
        assert_eq!(read(json!(["Alice", "bob"])), vec!["alice", "bob"]);
    }

    #[test]
    fn a_name_of_the_wrong_size_is_dropped_and_the_rest_survive() {
        assert_eq!(read(json!(["ab", "alice", "a".repeat(31)])), vec!["alice"]);
    }

    #[test]
    fn a_value_that_is_not_a_string_is_dropped() {
        assert_eq!(
            read(json!([1, null, {"a": 1}, ["alice"], "alice"])),
            vec!["alice"]
        );
    }

    #[test]
    fn only_the_first_twenty_entries_are_looked_at() {
        let many: Vec<String> = (0..MAX_MENTIONS + 5)
            .map(|index| format!("user{index:02}"))
            .collect();
        let kept = read(json!(many));
        assert_eq!(kept.len(), MAX_MENTIONS);
        assert_eq!(kept[0], "user00");
        assert_eq!(
            kept[MAX_MENTIONS - 1],
            format!("user{:02}", MAX_MENTIONS - 1)
        );
    }

    #[test]
    fn anything_that_is_not_a_list_mentions_nobody() {
        assert!(Mentions::read(None).is_empty());
        assert!(read(json!("alice")).is_empty());
        assert!(read(json!({"user": "alice"})).is_empty());
        assert!(read(json!(null)).is_empty());
    }
}
