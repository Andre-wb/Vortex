#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoDelete(Option<i64>);

impl AutoDelete {
    pub fn read(seconds: i64) -> Self {
        AutoDelete((seconds > 0).then_some(seconds))
    }

    pub fn seconds(&self) -> Option<i64> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlowMode(i64);

impl SlowMode {
    pub fn read(seconds: i64) -> Self {
        SlowMode(seconds.max(0))
    }

    pub fn seconds(&self) -> i64 {
        self.0
    }

    pub fn shown(stored: Option<i64>) -> i64 {
        stored.unwrap_or(0).max(0)
    }
}

#[cfg(test)]
mod tests {
    use super::{AutoDelete, SlowMode};

    #[test]
    fn switching_auto_delete_off_stores_nothing_rather_than_a_zero() {
        assert_eq!(AutoDelete::read(0).seconds(), None);
        assert_eq!(AutoDelete::read(-5).seconds(), None);
        assert_eq!(AutoDelete::read(30).seconds(), Some(30));
    }

    #[test]
    fn a_negative_slow_mode_is_no_slow_mode() {
        assert_eq!(SlowMode::read(-5).seconds(), 0);
        assert_eq!(SlowMode::read(0).seconds(), 0);
        assert_eq!(SlowMode::read(15).seconds(), 15);
    }

    #[test]
    fn a_room_that_never_set_slow_mode_shows_zero() {
        assert_eq!(SlowMode::shown(None), 0);
        assert_eq!(SlowMode::shown(Some(15)), 15);
        assert_eq!(SlowMode::shown(Some(-1)), 0);
    }
}
