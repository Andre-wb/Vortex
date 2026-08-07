use crate::mailbox::fetched::FetchedMessage;
use crate::mailbox::id::MailboxId;
use crate::store::refusal::DepositRefusal;
use crate::store::stats::StoreStats;

pub trait MailboxStore: Send + Sync {
    fn deposit(&self, mailbox: &MailboxId, ciphertext: &str) -> Result<(), DepositRefusal>;

    fn fetch(&self, mailbox: &MailboxId, since: f64) -> Vec<FetchedMessage>;

    fn fetch_batch(
        &self,
        mailboxes: &[MailboxId],
        since: f64,
    ) -> Vec<(MailboxId, Vec<FetchedMessage>)>;

    fn collect_garbage(&self) -> u64;

    fn stats(&self) -> StoreStats;
}
