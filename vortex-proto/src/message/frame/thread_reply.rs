use crate::message::frame::incoming::IncomingFrame;
use crate::message::frame::send::SendFrame;
use crate::message::reference::MessageId;
use crate::message::refusal::MessageRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadReplyFrame {
    pub thread_id: MessageId,
    pub message: SendFrame,
}

impl ThreadReplyFrame {
    pub fn read(frame: &IncomingFrame, now_microseconds: i64) -> Result<Self, MessageRefusal> {
        let thread_id =
            MessageId::read(frame.field("thread_id")).ok_or(MessageRefusal::ThreadIdMissing)?;
        Ok(ThreadReplyFrame {
            thread_id,
            message: SendFrame::read(frame, now_microseconds)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ThreadReplyFrame;
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

    #[test]
    fn a_reply_names_the_thread_it_belongs_to() {
        let parsed = ThreadReplyFrame::read(
            &frame(&format!(
                r#"{{"thread_id":5,"ciphertext":"{}","msg_id":"c-2"}}"#,
                ciphertext_hex()
            )),
            NOW,
        )
        .unwrap();
        assert_eq!(parsed.thread_id.value(), 5);
        assert_eq!(parsed.message.client_msg_id, "c-2");
    }

    #[test]
    fn the_thread_is_asked_for_before_the_ciphertext_is_measured() {
        assert_eq!(
            ThreadReplyFrame::read(&frame(r#"{"ciphertext":"ab"}"#), NOW),
            Err(MessageRefusal::ThreadIdMissing)
        );
    }

    #[test]
    fn a_reply_without_a_ciphertext_is_refused_by_its_content() {
        assert_eq!(
            ThreadReplyFrame::read(&frame(r#"{"thread_id":5}"#), NOW),
            Err(MessageRefusal::CiphertextMissing)
        );
    }

    #[test]
    fn a_thread_written_as_a_string_is_read() {
        let parsed = ThreadReplyFrame::read(
            &frame(&format!(
                r#"{{"thread_id":"5","ciphertext":"{}"}}"#,
                ciphertext_hex()
            )),
            NOW,
        )
        .unwrap();
        assert_eq!(parsed.thread_id.value(), 5);
    }
}
