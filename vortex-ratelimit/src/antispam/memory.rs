use std::collections::HashMap;

use parking_lot::RwLock;

use crate::antispam::digest::Digest;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::error::Result;
use crate::ports::repeat_ledger::RepeatLedger;
use crate::ports::window_reset::WindowReset;

pub const MAX_TRACKED_SUBJECTS: usize = 50_000;

pub struct MemoryRepeatLedger {
    seen: RwLock<HashMap<Subject, Vec<(f64, Digest)>>>,
    ceiling: usize,
}

impl Default for MemoryRepeatLedger {
    fn default() -> Self {
        MemoryRepeatLedger::new()
    }
}

impl MemoryRepeatLedger {
    pub fn new() -> Self {
        MemoryRepeatLedger::holding(MAX_TRACKED_SUBJECTS)
    }

    pub fn holding(ceiling: usize) -> Self {
        MemoryRepeatLedger {
            seen: RwLock::new(HashMap::new()),
            ceiling: ceiling.max(1),
        }
    }

    pub fn forget_stale(&self, window: Window, now: f64) {
        let width = window.width();
        let mut seen = self.seen.write();
        seen.retain(|_, entries| {
            entries.retain(|(stamp, _)| now - stamp < width);
            !entries.is_empty()
        });
    }

    pub fn tracked_subjects(&self) -> usize {
        self.seen.read().len()
    }
}

impl RepeatLedger for MemoryRepeatLedger {
    fn record(&self, subject: &Subject, digest: &Digest, window: Window, now: f64) -> Result<u32> {
        if self.tracked_subjects() >= self.ceiling {
            self.forget_stale(window, now);
        }

        let width = window.width();
        let mut seen = self.seen.write();
        let entries = seen.entry(subject.clone()).or_default();
        entries.retain(|(stamp, _)| now - stamp < width);
        entries.push((now, digest.clone()));

        let same = entries
            .iter()
            .filter(|(_, recorded)| recorded == digest)
            .count();
        Ok(u32::try_from(same).unwrap_or(u32::MAX))
    }
}

impl WindowReset for MemoryRepeatLedger {
    fn forget(&self, subject: &Subject) -> Result<()> {
        self.seen.write().remove(subject);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryRepeatLedger;
    use crate::antispam::digest::Digest;
    use crate::attempt::subject::Subject;
    use crate::attempt::window::Window;
    use crate::ports::repeat_ledger::RepeatLedger;
    use crate::ports::window_reset::WindowReset;

    const BASE: f64 = 1_000.0;

    fn window() -> Window {
        Window::seconds(30).unwrap()
    }

    fn membership(member: &str) -> Subject {
        Subject::of("antispam-repeats", member)
    }

    #[test]
    fn every_copy_of_one_message_raises_its_running_count() {
        let ledger = MemoryRepeatLedger::new();
        let text = Digest::of("stop");
        for expected in 1..=3 {
            assert_eq!(
                ledger
                    .record(&membership("1:7"), &text, window(), BASE)
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn a_different_message_never_counts_towards_a_repeat() {
        let ledger = MemoryRepeatLedger::new();
        ledger
            .record(&membership("1:7"), &Digest::of("stop"), window(), BASE)
            .unwrap();
        assert_eq!(
            ledger
                .record(&membership("1:7"), &Digest::of("start"), window(), BASE)
                .unwrap(),
            1
        );
    }

    #[test]
    fn a_copy_older_than_the_window_is_forgotten() {
        let ledger = MemoryRepeatLedger::new();
        let text = Digest::of("stop");
        ledger
            .record(&membership("1:7"), &text, window(), BASE)
            .unwrap();
        assert_eq!(
            ledger
                .record(&membership("1:7"), &text, window(), BASE + 30.0)
                .unwrap(),
            1
        );
    }

    #[test]
    fn one_membership_never_answers_for_another() {
        let ledger = MemoryRepeatLedger::new();
        let text = Digest::of("stop");
        ledger
            .record(&membership("1:7"), &text, window(), BASE)
            .unwrap();
        assert_eq!(
            ledger
                .record(&membership("2:7"), &text, window(), BASE)
                .unwrap(),
            1
        );
        assert_eq!(
            ledger
                .record(&membership("1:8"), &text, window(), BASE)
                .unwrap(),
            1
        );
    }

    #[test]
    fn forgetting_a_membership_clears_every_message_it_sent() {
        let ledger = MemoryRepeatLedger::new();
        let first = Digest::of("stop");
        let second = Digest::of("start");
        ledger
            .record(&membership("1:7"), &first, window(), BASE)
            .unwrap();
        ledger
            .record(&membership("1:7"), &second, window(), BASE)
            .unwrap();
        ledger.forget(&membership("1:7")).unwrap();
        assert_eq!(
            ledger
                .record(&membership("1:7"), &first, window(), BASE)
                .unwrap(),
            1
        );
        assert_eq!(
            ledger
                .record(&membership("1:7"), &second, window(), BASE)
                .unwrap(),
            1
        );
    }

    #[test]
    fn stale_subjects_are_forgotten_instead_of_growing_without_bound() {
        let ledger = MemoryRepeatLedger::new();
        let text = Digest::of("stop");
        for index in 0..100 {
            ledger
                .record(&membership(&format!("1:{index}")), &text, window(), BASE)
                .unwrap();
        }
        assert_eq!(ledger.tracked_subjects(), 100);
        ledger.forget_stale(window(), BASE + 30.0);
        assert_eq!(ledger.tracked_subjects(), 0);
    }

    #[test]
    fn reaching_the_ceiling_forgets_the_stale_instead_of_refusing_the_message() {
        let ledger = MemoryRepeatLedger::holding(4);
        let text = Digest::of("stop");
        for index in 0..4 {
            ledger
                .record(&membership(&format!("1:{index}")), &text, window(), BASE)
                .unwrap();
        }
        assert_eq!(
            ledger
                .record(&membership("9:9"), &text, window(), BASE + 30.0)
                .unwrap(),
            1
        );
        assert_eq!(ledger.tracked_subjects(), 1);
    }
}
