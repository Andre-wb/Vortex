#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    received: u32,
    total: u32,
    missing: Vec<u32>,
}

impl Progress {
    pub fn of(received: u32, total: u32, missing: Vec<u32>) -> Self {
        Progress {
            received,
            total,
            missing,
        }
    }

    pub fn received(&self) -> u32 {
        self.received
    }

    pub fn total(&self) -> u32 {
        self.total
    }

    pub fn missing(&self) -> &[u32] {
        &self.missing
    }

    pub fn complete(&self) -> bool {
        self.received >= self.total
    }

    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        let share = f64::from(self.received) / f64::from(self.total) * 100.0;
        (share * 10.0).round() / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::Progress;

    #[test]
    fn a_plan_with_no_chunks_is_complete_at_once() {
        let progress = Progress::of(0, 0, Vec::new());
        assert_eq!(progress.percent(), 100.0);
        assert!(progress.complete());
    }

    #[test]
    fn a_share_is_told_to_one_decimal_place() {
        assert_eq!(Progress::of(1, 3, vec![1, 2]).percent(), 33.3);
        assert_eq!(Progress::of(2, 3, vec![2]).percent(), 66.7);
    }

    #[test]
    fn a_full_plan_is_complete() {
        assert!(Progress::of(4, 4, Vec::new()).complete());
        assert!(!Progress::of(3, 4, vec![3]).complete());
    }
}
