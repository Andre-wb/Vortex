use crate::hex::encode::encode;
use crate::message::time::stored_stamp::stored_stamp;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMessage {
    pub msg_id: i64,
    pub sender_pseudo: Option<String>,
    pub msg_type: String,
    pub ciphertext: Option<String>,
    pub hash: Option<String>,
    pub enc_v: Option<u8>,
    pub file_name: Option<String>,
    pub file_size: Option<i64>,
    pub reply_to_id: Option<i64>,
    pub thread_id: Option<i64>,
    pub thread_count: i64,
    pub is_edited: bool,
    pub forwarded_from: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
}

pub struct StoredMessageDraft<'a> {
    pub msg_id: i64,
    pub sender_pseudo: Option<&'a str>,
    pub msg_type: &'a str,
    pub content: Option<&'a [u8]>,
    pub digest: Option<&'a [u8]>,
    pub enc_v: Option<u8>,
    pub file_name: Option<&'a str>,
    pub file_size: Option<i64>,
    pub reply_to_id: Option<i64>,
    pub thread_id: Option<i64>,
    pub thread_count: Option<i64>,
    pub is_edited: Option<bool>,
    pub forwarded_from: Option<&'a str>,
    pub expires_at: Option<(i64, u32)>,
    pub created_at: (i64, u32),
}

impl StoredMessage {
    pub fn render(draft: StoredMessageDraft<'_>) -> Self {
        StoredMessage {
            msg_id: draft.msg_id,
            sender_pseudo: draft.sender_pseudo.map(str::to_string),
            msg_type: draft.msg_type.to_string(),
            ciphertext: draft.content.map(encode),
            hash: draft.digest.map(encode),
            enc_v: draft.enc_v,
            file_name: draft.file_name.map(str::to_string),
            file_size: draft.file_size,
            reply_to_id: draft.reply_to_id,
            thread_id: draft.thread_id,
            thread_count: draft.thread_count.unwrap_or(0),
            is_edited: draft.is_edited.unwrap_or(false),
            forwarded_from: draft.forwarded_from.map(str::to_string),
            expires_at: draft
                .expires_at
                .map(|(seconds, micros)| stored_stamp(seconds, micros)),
            created_at: stored_stamp(draft.created_at.0, draft.created_at.1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{StoredMessage, StoredMessageDraft};

    fn draft<'a>() -> StoredMessageDraft<'a> {
        StoredMessageDraft {
            msg_id: 42,
            sender_pseudo: Some("pseudo"),
            msg_type: "text",
            content: Some(&[0xab, 0xcd]),
            digest: Some(&[0x01, 0x02]),
            enc_v: Some(1),
            file_name: None,
            file_size: None,
            reply_to_id: None,
            thread_id: None,
            thread_count: None,
            is_edited: None,
            forwarded_from: None,
            expires_at: None,
            created_at: (1_785_834_930, 0),
        }
    }

    #[test]
    fn stored_bytes_are_shown_as_hex() {
        let stored = StoredMessage::render(draft());
        assert_eq!(stored.ciphertext.as_deref(), Some("abcd"));
        assert_eq!(stored.hash.as_deref(), Some("0102"));
    }

    #[test]
    fn a_message_without_content_shows_nothing_in_its_place() {
        let stored = StoredMessage::render(StoredMessageDraft {
            content: None,
            digest: None,
            ..draft()
        });
        assert_eq!(stored.ciphertext, None);
        assert_eq!(stored.hash, None);
    }

    #[test]
    fn a_stored_stamp_carries_its_fraction_and_no_zone() {
        let stored = StoredMessage::render(StoredMessageDraft {
            created_at: (1_785_834_930, 789_012),
            expires_at: Some((1_785_834_990, 0)),
            ..draft()
        });
        assert_eq!(stored.created_at, "2026-08-04T09:15:30.789012");
        assert_eq!(stored.expires_at.as_deref(), Some("2026-08-04T09:16:30"));
    }

    #[test]
    fn counters_and_flags_that_were_never_set_read_as_empty() {
        let stored = StoredMessage::render(draft());
        assert_eq!(stored.thread_count, 0);
        assert!(!stored.is_edited);
    }
}
