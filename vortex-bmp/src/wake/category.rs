use sha2::{Digest, Sha256};

use crate::mailbox::id::MailboxId;

pub fn wake_category(mailbox: &MailboxId) -> u8 {
    Sha256::digest(mailbox.as_str().as_bytes())[0]
}

#[cfg(test)]
mod tests {
    use super::wake_category;
    use crate::mailbox::id::MailboxId;

    fn mailbox(value: &str) -> MailboxId {
        MailboxId::parse(value).unwrap()
    }

    #[test]
    fn the_category_of_a_mailbox_never_changes() {
        let id = mailbox("0123456789abcdef");
        assert_eq!(wake_category(&id), wake_category(&id));
    }

    #[test]
    fn the_category_is_the_first_byte_of_the_digest() {
        assert_eq!(wake_category(&mailbox("0123456789abcdef")), 0x9f);
    }

    #[test]
    fn different_mailboxes_land_in_different_categories() {
        assert_ne!(
            wake_category(&mailbox("0123456789abcdef")),
            wake_category(&mailbox("fedcba9876543210"))
        );
    }
}
