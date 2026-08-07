#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreStats {
    pub active_mailboxes: usize,
    pub total_messages: usize,
    pub stored_bytes: usize,
    pub total_deposited: u64,
    pub total_fetched: u64,
    pub total_expired: u64,
    pub total_refused: u64,
}
