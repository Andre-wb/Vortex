use crate::attempt::subject::Subject;
use crate::error::{CountError, Result};
use crate::ports::strike_ledger::StrikeLedger;

pub struct UnavailableStrikeLedger;

impl Default for UnavailableStrikeLedger {
    fn default() -> Self {
        UnavailableStrikeLedger::new()
    }
}

impl UnavailableStrikeLedger {
    pub fn new() -> Self {
        UnavailableStrikeLedger
    }
}

impl StrikeLedger for UnavailableStrikeLedger {
    fn strike(&self, _subject: &Subject) -> Result<u32> {
        Err(CountError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableStrikeLedger;
    use crate::attempt::subject::Subject;
    use crate::error::CountError;
    use crate::ports::strike_ledger::StrikeLedger;

    #[test]
    fn a_penalty_nobody_can_record_is_never_reported_as_recorded() {
        let ledger = UnavailableStrikeLedger::new();
        assert_eq!(
            ledger.strike(&Subject::of("flood-strikes", "1:7")),
            Err(CountError::Unavailable)
        );
    }
}
