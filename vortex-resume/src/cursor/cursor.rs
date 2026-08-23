use crate::cursor::identifier::ClientKey;
use crate::cursor::limits;

#[derive(Debug, Clone, PartialEq)]
pub struct Cursor {
    key: ClientKey,
    mailbox_stamp: f64,
    rooms: Vec<i64>,
    saved_at: f64,
}

impl Cursor {
    pub fn of(key: ClientKey, mailbox_stamp: f64, rooms: &[i64], saved_at: f64) -> Self {
        Cursor {
            key,
            mailbox_stamp: settled(mailbox_stamp),
            rooms: tidied(rooms),
            saved_at,
        }
    }

    pub fn key(&self) -> &ClientKey {
        &self.key
    }

    pub fn mailbox_stamp(&self) -> f64 {
        self.mailbox_stamp
    }

    pub fn rooms(&self) -> &[i64] {
        &self.rooms
    }

    pub fn saved_at(&self) -> f64 {
        self.saved_at
    }

    pub fn deadline(&self) -> f64 {
        self.saved_at + limits::CURSOR_LIFETIME_SECONDS
    }

    pub fn stale(&self, now: f64) -> bool {
        now >= self.deadline()
    }
}

fn settled(stamp: f64) -> f64 {
    if stamp.is_finite() && stamp > 0.0 {
        stamp
    } else {
        0.0
    }
}

fn tidied(rooms: &[i64]) -> Vec<i64> {
    let mut tidy: Vec<i64> = rooms.to_vec();
    tidy.sort_unstable();
    tidy.dedup();
    tidy.truncate(limits::MAX_ROOMS);
    tidy
}

#[cfg(test)]
mod tests {
    use super::Cursor;
    use crate::cursor::identifier::ClientKey;
    use crate::cursor::limits;

    fn key() -> ClientKey {
        ClientKey::parse("abcd").unwrap()
    }

    #[test]
    fn rooms_are_kept_sorted_and_without_repeats() {
        let cursor = Cursor::of(key(), 1.0, &[9, 3, 9, 1], 100.0);
        assert_eq!(cursor.rooms(), &[1, 3, 9]);
    }

    #[test]
    fn a_stamp_before_the_epoch_settles_at_zero() {
        assert_eq!(Cursor::of(key(), -5.0, &[], 100.0).mailbox_stamp(), 0.0);
        assert_eq!(Cursor::of(key(), f64::NAN, &[], 100.0).mailbox_stamp(), 0.0);
    }

    #[test]
    fn a_room_list_is_cut_at_the_agreed_limit() {
        let many: Vec<i64> = (1..=(limits::MAX_ROOMS as i64 + 10)).collect();
        assert_eq!(
            Cursor::of(key(), 1.0, &many, 100.0).rooms().len(),
            limits::MAX_ROOMS
        );
    }

    #[test]
    fn a_cursor_goes_stale_at_its_deadline_and_not_before() {
        let cursor = Cursor::of(key(), 1.0, &[], 100.0);
        assert!(!cursor.stale(100.0 + limits::CURSOR_LIFETIME_SECONDS - 0.001));
        assert!(cursor.stale(100.0 + limits::CURSOR_LIFETIME_SECONDS));
    }
}
