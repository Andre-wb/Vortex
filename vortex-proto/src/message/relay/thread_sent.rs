use crate::message::relay::sender::Sender;
use crate::message::relay::sent::STATUS_SENT;
use crate::message::time::wire_stamp::wire_stamp;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadMessage {
    pub msg_id: i64,
    pub client_msg_id: String,
    pub thread_id: i64,
    pub sender: Sender,
    pub ciphertext: String,
    pub hash: String,
    pub enc_v: Option<u8>,
    pub reply_to_id: Option<i64>,
    pub reply_quote: Option<String>,
    pub created_at: String,
    pub status: &'static str,
}

pub struct ThreadMessageDraft<'a> {
    pub msg_id: i64,
    pub client_msg_id: &'a str,
    pub thread_id: i64,
    pub sender: Sender,
    pub ciphertext: &'a str,
    pub hash: &'a str,
    pub enc_v: Option<u8>,
    pub reply_to_id: Option<i64>,
    pub reply_quote: Option<&'a str>,
    pub created_at: i64,
}

impl ThreadMessage {
    pub fn render(draft: ThreadMessageDraft<'_>) -> Self {
        ThreadMessage {
            msg_id: draft.msg_id,
            client_msg_id: draft.client_msg_id.to_string(),
            thread_id: draft.thread_id,
            sender: draft.sender,
            ciphertext: draft.ciphertext.to_string(),
            hash: draft.hash.to_string(),
            enc_v: draft.enc_v,
            reply_to_id: draft.reply_to_id,
            reply_quote: draft.reply_quote.map(str::to_string),
            created_at: wire_stamp(draft.created_at),
            status: STATUS_SENT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ThreadMessage, ThreadMessageDraft};
    use crate::message::relay::sender::Sender;
    use crate::message::relay::sent::STATUS_SENT;

    #[test]
    fn a_thread_reply_carries_the_thread_it_belongs_to() {
        let message = ThreadMessage::render(ThreadMessageDraft {
            msg_id: 43,
            client_msg_id: "c-2",
            thread_id: 42,
            sender: Sender::named("bob", None),
            ciphertext: "abab",
            hash: "cdcd",
            enc_v: None,
            reply_to_id: None,
            reply_quote: None,
            created_at: 1_785_834_930,
        });
        assert_eq!(message.thread_id, 42);
        assert_eq!(message.created_at, "2026-08-04T09:15:30Z");
        assert_eq!(message.status, STATUS_SENT);
        assert_eq!(message.sender.shown_name(), "bob");
    }
}
