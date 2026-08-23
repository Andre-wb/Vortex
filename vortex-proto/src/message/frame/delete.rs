use crate::message::frame::incoming::IncomingFrame;
use crate::message::reference::MessageId;
use crate::message::refusal::MessageRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteFrame {
    pub msg_id: MessageId,
}

impl DeleteFrame {
    pub fn read(frame: &IncomingFrame) -> Result<Self, MessageRefusal> {
        let msg_id =
            MessageId::read(frame.field("msg_id")).ok_or(MessageRefusal::MessageIdMissing)?;
        Ok(DeleteFrame { msg_id })
    }
}

#[cfg(test)]
mod tests {
    use super::DeleteFrame;
    use crate::message::frame::incoming::IncomingFrame;
    use crate::message::refusal::MessageRefusal;

    fn frame(payload: &str) -> IncomingFrame {
        IncomingFrame::from_json(payload).unwrap()
    }

    #[test]
    fn a_deletion_names_the_message_it_removes() {
        assert_eq!(
            DeleteFrame::read(&frame(r#"{"msg_id":9}"#))
                .unwrap()
                .msg_id
                .value(),
            9
        );
    }

    #[test]
    fn a_deletion_without_a_message_is_refused() {
        assert_eq!(
            DeleteFrame::read(&frame(r#"{"action":"delete_message"}"#)),
            Err(MessageRefusal::MessageIdMissing)
        );
    }

    #[test]
    fn a_message_that_is_not_an_identifier_is_refused() {
        for payload in [
            r#"{"msg_id":"abc"}"#,
            r#"{"msg_id":true}"#,
            r#"{"msg_id":1.5}"#,
            r#"{"msg_id":null}"#,
        ] {
            assert_eq!(
                DeleteFrame::read(&frame(payload)),
                Err(MessageRefusal::MessageIdMissing),
                "{payload}"
            );
        }
    }
}
