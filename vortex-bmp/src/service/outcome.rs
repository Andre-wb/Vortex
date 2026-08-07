use crate::mailbox::fetched::FetchedMessage;
use crate::mailbox::id::MailboxId;
use crate::store::refusal::DepositRefusal;

#[derive(Debug, Clone, PartialEq)]
pub struct BatchOutcome {
    pub mailboxes: Vec<(MailboxId, Vec<FetchedMessage>)>,
    pub padding: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EnvelopeOutcome {
    Deposited {
        mailboxes: Vec<MailboxId>,
        wake_categories: Vec<u8>,
    },
    UnknownRoom,
    Refused(DepositRefusal),
}

impl EnvelopeOutcome {
    pub fn is_deposited(&self) -> bool {
        matches!(self, EnvelopeOutcome::Deposited { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::EnvelopeOutcome;
    use crate::store::refusal::DepositRefusal;

    #[test]
    fn only_a_deposit_counts_as_success() {
        assert!(EnvelopeOutcome::Deposited {
            mailboxes: vec![],
            wake_categories: vec![]
        }
        .is_deposited());
        assert!(!EnvelopeOutcome::UnknownRoom.is_deposited());
        assert!(!EnvelopeOutcome::Refused(DepositRefusal::AtCapacity).is_deposited());
    }
}
