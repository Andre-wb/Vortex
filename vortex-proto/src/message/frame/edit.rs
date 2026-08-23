use crate::message::frame::content::MessageContent;
use crate::message::frame::incoming::IncomingFrame;
use crate::message::reference::MessageId;
use crate::message::refusal::MessageRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditFrame {
    pub msg_id: MessageId,
    pub content: MessageContent,
}

impl EditFrame {
    pub fn read(frame: &IncomingFrame) -> Result<Self, MessageRefusal> {
        let msg_id =
            MessageId::read(frame.field("msg_id")).ok_or(MessageRefusal::MessageIdMissing)?;
        Ok(EditFrame {
            msg_id,
            content: MessageContent::read(frame)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::EditFrame;
    use crate::message::frame::incoming::IncomingFrame;
    use crate::message::refusal::MessageRefusal;

    fn frame(payload: &str) -> IncomingFrame {
        IncomingFrame::from_json(payload).unwrap()
    }

    fn ciphertext_hex() -> String {
        "cd".repeat(30)
    }

    #[test]
    fn an_edit_names_the_message_it_rewrites() {
        let parsed = EditFrame::read(&frame(&format!(
            r#"{{"msg_id":9,"ciphertext":"{}","enc_v":1}}"#,
            ciphertext_hex()
        )))
        .unwrap();
        assert_eq!(parsed.msg_id.value(), 9);
        assert_eq!(parsed.content.enc_version.unwrap().value(), 1);
    }

    #[test]
    fn the_message_is_asked_for_before_the_ciphertext_is_measured() {
        assert_eq!(
            EditFrame::read(&frame(r#"{"ciphertext":"ab"}"#)),
            Err(MessageRefusal::MessageIdMissing)
        );
    }

    #[test]
    fn an_edit_that_carries_no_new_text_is_refused() {
        assert_eq!(
            EditFrame::read(&frame(r#"{"msg_id":9}"#)),
            Err(MessageRefusal::CiphertextMissing)
        );
    }

    #[test]
    fn an_edit_shorter_than_a_ciphertext_can_be_is_refused() {
        assert_eq!(
            EditFrame::read(&frame(r#"{"msg_id":9,"ciphertext":"abcd"}"#)),
            Err(MessageRefusal::CiphertextShort)
        );
    }
}
