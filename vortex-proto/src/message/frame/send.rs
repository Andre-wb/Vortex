use crate::message::frame::content::MessageContent;
use crate::message::frame::incoming::IncomingFrame;
use crate::message::mentions::Mentions;
use crate::message::reference::MessageId;
use crate::message::refusal::MessageRefusal;
use crate::message::time::client_stamp::ClientStamp;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendFrame {
    pub client_msg_id: String,
    pub content: MessageContent,
    pub reply_to: Option<MessageId>,
    pub reply_quote: Option<String>,
    pub mentions: Mentions,
    pub client_stamp: Option<i64>,
}

impl SendFrame {
    pub fn read(frame: &IncomingFrame, now_microseconds: i64) -> Result<Self, MessageRefusal> {
        let content = MessageContent::read(frame)?;
        Ok(SendFrame {
            client_msg_id: frame.scalar_text("msg_id"),
            content,
            reply_to: MessageId::read(frame.field("reply_to_id")),
            reply_quote: quote(frame),
            mentions: Mentions::read(frame.field("mentioned_usernames")),
            client_stamp: ClientStamp::within_window(frame.text("client_ts"), now_microseconds),
        })
    }
}

fn quote(frame: &IncomingFrame) -> Option<String> {
    let text = frame.text("reply_quote");
    (!text.is_empty()).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::SendFrame;
    use crate::message::frame::incoming::IncomingFrame;
    use crate::message::refusal::MessageRefusal;
    use crate::message::time::client_stamp::MICROS_PER_SECOND;

    const NOW: i64 = 1_785_834_930 * MICROS_PER_SECOND;

    fn frame(payload: &str) -> IncomingFrame {
        IncomingFrame::from_json(payload).unwrap()
    }

    fn ciphertext_hex() -> String {
        "ab".repeat(30)
    }

    fn plain() -> String {
        format!(
            r#"{{"action":"message","ciphertext":"{}","msg_id":"c-1"}}"#,
            ciphertext_hex()
        )
    }

    #[test]
    fn a_plain_message_carries_its_client_identifier_and_nothing_else() {
        let parsed = SendFrame::read(&frame(&plain()), NOW).unwrap();
        assert_eq!(parsed.client_msg_id, "c-1");
        assert_eq!(parsed.reply_to, None);
        assert_eq!(parsed.reply_quote, None);
        assert!(parsed.mentions.is_empty());
        assert_eq!(parsed.client_stamp, None);
    }

    #[test]
    fn a_reply_carries_the_message_it_answers_and_its_quote() {
        let parsed = SendFrame::read(
            &frame(&format!(
                r#"{{"ciphertext":"{}","reply_to_id":12,"reply_quote":"hi"}}"#,
                ciphertext_hex()
            )),
            NOW,
        )
        .unwrap();
        assert_eq!(parsed.reply_to.unwrap().value(), 12);
        assert_eq!(parsed.reply_quote.as_deref(), Some("hi"));
    }

    #[test]
    fn an_empty_quote_is_no_quote() {
        let parsed = SendFrame::read(
            &frame(&format!(
                r#"{{"ciphertext":"{}","reply_quote":""}}"#,
                ciphertext_hex()
            )),
            NOW,
        )
        .unwrap();
        assert_eq!(parsed.reply_quote, None);
    }

    #[test]
    fn a_stamp_inside_the_window_is_kept_and_one_outside_it_is_dropped() {
        let inside = SendFrame::read(
            &frame(&format!(
                r#"{{"ciphertext":"{}","client_ts":"2026-08-04T09:15:30Z"}}"#,
                ciphertext_hex()
            )),
            NOW,
        )
        .unwrap();
        let outside = SendFrame::read(
            &frame(&format!(
                r#"{{"ciphertext":"{}","client_ts":"2020-01-01T00:00:00Z"}}"#,
                ciphertext_hex()
            )),
            NOW,
        )
        .unwrap();
        assert_eq!(inside.client_stamp, Some(NOW));
        assert_eq!(outside.client_stamp, None);
    }

    #[test]
    fn mentions_are_read_from_the_frame() {
        let parsed = SendFrame::read(
            &frame(&format!(
                r#"{{"ciphertext":"{}","mentioned_usernames":["Alice","x"]}}"#,
                ciphertext_hex()
            )),
            NOW,
        )
        .unwrap();
        assert_eq!(parsed.mentions.names(), vec!["alice"]);
    }

    #[test]
    fn a_frame_without_a_ciphertext_is_refused() {
        assert_eq!(
            SendFrame::read(&frame(r#"{"action":"message"}"#), NOW),
            Err(MessageRefusal::CiphertextMissing)
        );
    }

    #[test]
    fn a_client_identifier_written_as_a_number_is_read_as_text() {
        let parsed = SendFrame::read(
            &frame(&format!(
                r#"{{"ciphertext":"{}","msg_id":7}}"#,
                ciphertext_hex()
            )),
            NOW,
        )
        .unwrap();
        assert_eq!(parsed.client_msg_id, "7");
    }
}
