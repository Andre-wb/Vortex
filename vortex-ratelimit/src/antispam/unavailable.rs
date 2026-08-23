use crate::antispam::digest::Digest;
use crate::attempt::subject::Subject;
use crate::attempt::window::Window;
use crate::error::{CountError, Result};
use crate::ports::repeat_ledger::RepeatLedger;

pub struct UnavailableRepeatLedger;

impl Default for UnavailableRepeatLedger {
    fn default() -> Self {
        UnavailableRepeatLedger::new()
    }
}

impl UnavailableRepeatLedger {
    pub fn new() -> Self {
        UnavailableRepeatLedger
    }
}

impl RepeatLedger for UnavailableRepeatLedger {
    fn record(
        &self,
        _subject: &Subject,
        _digest: &Digest,
        _window: Window,
        _now: f64,
    ) -> Result<u32> {
        Err(CountError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableRepeatLedger;
    use crate::antispam::digest::Digest;
    use crate::attempt::subject::Subject;
    use crate::attempt::window::Window;
    use crate::error::CountError;
    use crate::ports::repeat_ledger::RepeatLedger;

    #[test]
    fn a_copy_nobody_can_count_is_never_reported_as_counted() {
        let ledger = UnavailableRepeatLedger::new();
        assert_eq!(
            ledger.record(
                &Subject::of("antispam-repeats", "1:7"),
                &Digest::of("stop"),
                Window::seconds(30).unwrap(),
                1_000.0
            ),
            Err(CountError::Unavailable)
        );
    }
}
