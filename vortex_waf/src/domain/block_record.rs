//! Запись о временной блокировке адреса.

use crate::domain::timestamp::Timestamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRecord {
    pub blocked_at: Timestamp,
    pub until: Timestamp,
    pub reason: String,
    pub duration_secs: u64,
}

impl BlockRecord {
    pub fn new(blocked_at: Timestamp, duration_secs: u64, reason: impl Into<String>) -> Self {
        BlockRecord {
            blocked_at,
            until: blocked_at.plus_secs(duration_secs),
            reason: reason.into(),
            duration_secs,
        }
    }

    pub fn is_active_at(&self, now: Timestamp) -> bool {
        self.until > now
    }
}

#[cfg(test)]
mod tests {
    use super::BlockRecord;
    use crate::domain::timestamp::Timestamp;

    #[test]
    fn expires_exactly_at_until() {
        let t0 = Timestamp::from_unix_secs(1_000);
        let record = BlockRecord::new(t0, 60, "manual");
        assert!(record.is_active_at(t0.plus_secs(59)));
        assert!(!record.is_active_at(t0.plus_secs(60)));
    }
}
