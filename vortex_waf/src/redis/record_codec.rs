//! Кодирование записи о блокировке для Redis.
//!
//! Формат: `<начало, мс>|<конец, мс>|<длительность, с>|<причина>`. Причина идёт
//! последней и может содержать любые символы, включая разделитель.

use crate::domain::block_record::BlockRecord;
use crate::domain::timestamp::Timestamp;

pub fn encode(record: &BlockRecord) -> String {
    format!(
        "{}|{}|{}|{}",
        record.blocked_at.unix_millis(),
        record.until.unix_millis(),
        record.duration_secs,
        record.reason
    )
}

pub fn decode(payload: &str) -> Option<BlockRecord> {
    let mut parts = payload.splitn(4, '|');
    let blocked_at = parts.next()?.parse::<i64>().ok()?;
    let until = parts.next()?.parse::<i64>().ok()?;
    let duration_secs = parts.next()?.parse::<u64>().ok()?;
    let reason = parts.next()?;

    Some(BlockRecord {
        blocked_at: Timestamp::from_unix_millis(blocked_at),
        until: Timestamp::from_unix_millis(until),
        reason: reason.to_string(),
        duration_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::domain::block_record::BlockRecord;
    use crate::domain::timestamp::Timestamp;

    fn record(reason: &str) -> BlockRecord {
        BlockRecord::new(Timestamp::from_unix_secs(1_700_000_000), 60, reason)
    }

    #[test]
    fn a_record_survives_the_round_trip() {
        let original = record("manual");
        assert_eq!(decode(&encode(&original)), Some(original));
    }

    #[test]
    fn a_reason_with_separators_survives_intact() {
        let original = record("rate limit | exceeded | twice");
        assert_eq!(decode(&encode(&original)).unwrap().reason, original.reason);
    }

    #[test]
    fn a_deadline_keeps_millisecond_precision() {
        let original = BlockRecord {
            blocked_at: Timestamp::from_unix_millis(1_700_000_000_123),
            until: Timestamp::from_unix_millis(1_700_000_060_456),
            reason: "manual".to_string(),
            duration_secs: 60,
        };
        assert_eq!(decode(&encode(&original)), Some(original));
    }

    #[test]
    fn garbage_decodes_to_nothing() {
        assert_eq!(decode(""), None);
        assert_eq!(decode("не|число|60|manual"), None);
        assert_eq!(decode("1|2|3"), None);
    }
}
