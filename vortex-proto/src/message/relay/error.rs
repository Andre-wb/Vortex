use crate::message::refusal::MessageRefusal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorFrame {
    pub message: &'static str,
    pub code: &'static str,
}

impl ErrorFrame {
    pub fn of(refusal: MessageRefusal) -> Self {
        ErrorFrame {
            message: refusal.message(),
            code: refusal.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorFrame;
    use crate::message::refusal::MessageRefusal;

    #[test]
    fn a_refusal_is_told_to_the_client_in_full() {
        let frame = ErrorFrame::of(MessageRefusal::CiphertextShort);
        assert_eq!(frame.message, "Ciphertext too short");
        assert_eq!(frame.code, "ciphertext_short");
    }

    #[test]
    fn every_refusal_can_be_told_to_a_client() {
        for refusal in [
            MessageRefusal::CiphertextMissing,
            MessageRefusal::CiphertextShort,
            MessageRefusal::CiphertextLarge,
            MessageRefusal::CiphertextHex,
            MessageRefusal::MessageIdMissing,
            MessageRefusal::ThreadIdMissing,
            MessageRefusal::FrameTooLarge,
        ] {
            let frame = ErrorFrame::of(refusal);
            assert!(!frame.message.is_empty());
            assert!(!frame.code.is_empty());
        }
    }
}
