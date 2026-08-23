use crate::message::relay::sender::Sender;
use crate::message::time::wire_stamp::wire_stamp;

pub const STATUS_SENT: &str = "sent";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentMessage {
    pub msg_id: i64,
    pub client_msg_id: String,
    pub sender: Sender,
    pub ciphertext: String,
    pub hash: String,
    pub enc_v: Option<u8>,
    pub reply_to_id: Option<i64>,
    pub reply_quote: Option<String>,
    pub forwarded_from: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub status: &'static str,
}

pub struct SentMessageDraft<'a> {
    pub msg_id: i64,
    pub client_msg_id: &'a str,
    pub sender: Sender,
    pub ciphertext: &'a str,
    pub hash: &'a str,
    pub enc_v: Option<u8>,
    pub reply_to_id: Option<i64>,
    pub reply_quote: Option<&'a str>,
    pub forwarded_from: Option<&'a str>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

impl SentMessage {
    pub fn render(draft: SentMessageDraft<'_>) -> Self {
        SentMessage {
            msg_id: draft.msg_id,
            client_msg_id: draft.client_msg_id.to_string(),
            sender: draft.sender,
            ciphertext: draft.ciphertext.to_string(),
            hash: draft.hash.to_string(),
            enc_v: draft.enc_v,
            reply_to_id: draft.reply_to_id,
            reply_quote: draft.reply_quote.map(str::to_string),
            forwarded_from: draft.forwarded_from.map(str::to_string),
            expires_at: draft.expires_at.map(wire_stamp),
            created_at: wire_stamp(draft.created_at),
            status: STATUS_SENT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SentMessage, SentMessageDraft, STATUS_SENT};
    use crate::message::relay::sender::Sender;

    fn draft<'a>() -> SentMessageDraft<'a> {
        SentMessageDraft {
            msg_id: 42,
            client_msg_id: "c-1",
            sender: Sender::named("alice", Some("Alice")),
            ciphertext: "abab",
            hash: "cdcd",
            enc_v: Some(2),
            reply_to_id: None,
            reply_quote: None,
            forwarded_from: None,
            expires_at: None,
            created_at: 1_785_834_930,
        }
    }

    #[test]
    fn a_message_is_relayed_with_the_stamp_the_wire_uses() {
        let message = SentMessage::render(draft());
        assert_eq!(message.created_at, "2026-08-04T09:15:30Z");
        assert_eq!(message.expires_at, None);
        assert_eq!(message.status, STATUS_SENT);
    }

    #[test]
    fn a_message_that_expires_says_when() {
        let message = SentMessage::render(SentMessageDraft {
            expires_at: Some(1_785_834_990),
            ..draft()
        });
        assert_eq!(message.expires_at.as_deref(), Some("2026-08-04T09:16:30Z"));
    }

    #[test]
    fn the_sender_is_relayed_by_the_name_it_is_shown_under() {
        let message = SentMessage::render(draft());
        assert_eq!(message.sender.username, "alice");
        assert_eq!(message.sender.shown_name(), "Alice");
    }

    #[test]
    fn a_reply_carries_what_it_answers() {
        let message = SentMessage::render(SentMessageDraft {
            reply_to_id: Some(7),
            reply_quote: Some("hi"),
            ..draft()
        });
        assert_eq!(message.reply_to_id, Some(7));
        assert_eq!(message.reply_quote.as_deref(), Some("hi"));
    }
}
