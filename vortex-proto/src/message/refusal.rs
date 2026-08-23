#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageRefusal {
    CiphertextMissing,
    CiphertextShort,
    CiphertextLarge,
    CiphertextHex,
    MessageIdMissing,
    ThreadIdMissing,
    FrameTooLarge,
}

impl MessageRefusal {
    pub fn message(&self) -> &'static str {
        match self {
            MessageRefusal::CiphertextMissing => "Ciphertext is required",
            MessageRefusal::CiphertextShort => "Ciphertext too short",
            MessageRefusal::CiphertextLarge => "Ciphertext too large",
            MessageRefusal::CiphertextHex => "Ciphertext is not valid hex",
            MessageRefusal::MessageIdMissing => "Message id is required",
            MessageRefusal::ThreadIdMissing => "Thread id is required",
            MessageRefusal::FrameTooLarge => "Message too large",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            MessageRefusal::CiphertextMissing => "ciphertext_required",
            MessageRefusal::CiphertextShort => "ciphertext_short",
            MessageRefusal::CiphertextLarge => "ciphertext_large",
            MessageRefusal::CiphertextHex => "ciphertext_hex",
            MessageRefusal::MessageIdMissing => "message_id_required",
            MessageRefusal::ThreadIdMissing => "thread_id_required",
            MessageRefusal::FrameTooLarge => "frame_too_large",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MessageRefusal;

    const EVERY: [MessageRefusal; 7] = [
        MessageRefusal::CiphertextMissing,
        MessageRefusal::CiphertextShort,
        MessageRefusal::CiphertextLarge,
        MessageRefusal::CiphertextHex,
        MessageRefusal::MessageIdMissing,
        MessageRefusal::ThreadIdMissing,
        MessageRefusal::FrameTooLarge,
    ];

    #[test]
    fn every_refusal_says_something_and_is_named() {
        for refusal in EVERY {
            assert!(!refusal.message().is_empty());
            assert!(!refusal.code().is_empty());
        }
    }

    #[test]
    fn no_two_refusals_share_a_code() {
        for (index, refusal) in EVERY.iter().enumerate() {
            for other in &EVERY[index + 1..] {
                assert_ne!(refusal.code(), other.code());
            }
        }
    }

    #[test]
    fn the_wordings_that_clients_already_know_are_kept() {
        assert_eq!(
            MessageRefusal::CiphertextShort.message(),
            "Ciphertext too short"
        );
        assert_eq!(
            MessageRefusal::CiphertextLarge.message(),
            "Ciphertext too large"
        );
        assert_eq!(
            MessageRefusal::CiphertextHex.message(),
            "Ciphertext is not valid hex"
        );
        assert_eq!(MessageRefusal::FrameTooLarge.message(), "Message too large");
    }
}
