use crate::registry::limits;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodePubkey(String);

impl NodePubkey {
    pub fn parse(value: &str) -> Option<Self> {
        if value.len() != limits::PUBKEY_LENGTH {
            return None;
        }
        if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(NodePubkey(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }

    pub fn shortened(&self) -> String {
        format!("{}...", &self.0[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::NodePubkey;

    #[test]
    fn a_thirty_two_byte_key_names_a_node() {
        let key = "ab".repeat(32);
        assert_eq!(NodePubkey::parse(&key).unwrap().written(), key);
    }

    #[test]
    fn a_key_of_the_wrong_length_names_no_node() {
        assert!(NodePubkey::parse(&"ab".repeat(31)).is_none());
        assert!(NodePubkey::parse("").is_none());
    }

    #[test]
    fn a_key_outside_the_hex_alphabet_names_no_node() {
        assert!(NodePubkey::parse(&"z".repeat(64)).is_none());
    }

    #[test]
    fn a_key_is_shown_shortened_the_way_python_showed_it() {
        assert_eq!(
            NodePubkey::parse(&"ab".repeat(32)).unwrap().shortened(),
            "abababababababab..."
        );
    }
}
