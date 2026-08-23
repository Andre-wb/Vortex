#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditedMessage {
    pub msg_id: i64,
    pub ciphertext: String,
    pub enc_v: Option<u8>,
    pub is_edited: bool,
}

impl EditedMessage {
    pub fn render(msg_id: i64, ciphertext: &str, enc_v: Option<u8>) -> Self {
        EditedMessage {
            msg_id,
            ciphertext: ciphertext.to_string(),
            enc_v,
            is_edited: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EditedMessage;

    #[test]
    fn an_edit_is_always_announced_as_edited() {
        let edited = EditedMessage::render(9, "abab", Some(1));
        assert!(edited.is_edited);
        assert_eq!(edited.msg_id, 9);
        assert_eq!(edited.ciphertext, "abab");
        assert_eq!(edited.enc_v, Some(1));
    }

    #[test]
    fn an_edit_of_a_pre_versioning_message_carries_no_version() {
        assert_eq!(EditedMessage::render(9, "abab", None).enc_v, None);
    }
}
