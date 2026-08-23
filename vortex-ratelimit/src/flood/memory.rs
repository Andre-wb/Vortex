use std::collections::HashMap;

use parking_lot::RwLock;

use crate::attempt::subject::Subject;
use crate::error::Result;
use crate::ports::strike_ledger::StrikeLedger;

pub struct MemoryStrikeLedger {
    counted: RwLock<HashMap<Subject, u32>>,
}

impl Default for MemoryStrikeLedger {
    fn default() -> Self {
        MemoryStrikeLedger::new()
    }
}

impl MemoryStrikeLedger {
    pub fn new() -> Self {
        MemoryStrikeLedger {
            counted: RwLock::new(HashMap::new()),
        }
    }

    pub fn tracked_subjects(&self) -> usize {
        self.counted.read().len()
    }
}

impl StrikeLedger for MemoryStrikeLedger {
    fn strike(&self, subject: &Subject) -> Result<u32> {
        let mut counted = self.counted.write();
        let strikes = counted.entry(subject.clone()).or_insert(0);
        *strikes += 1;
        Ok(*strikes)
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryStrikeLedger;
    use crate::attempt::subject::Subject;
    use crate::ports::strike_ledger::StrikeLedger;

    fn membership(member: &str) -> Subject {
        Subject::of("flood-strikes", member)
    }

    #[test]
    fn every_penalty_raises_the_running_count() {
        let ledger = MemoryStrikeLedger::new();
        assert_eq!(ledger.strike(&membership("1:7")).unwrap(), 1);
        assert_eq!(ledger.strike(&membership("1:7")).unwrap(), 2);
        assert_eq!(ledger.strike(&membership("1:7")).unwrap(), 3);
    }

    #[test]
    fn one_membership_never_earns_a_penalty_for_another() {
        let ledger = MemoryStrikeLedger::new();
        ledger.strike(&membership("1:7")).unwrap();
        ledger.strike(&membership("1:7")).unwrap();
        assert_eq!(ledger.strike(&membership("2:7")).unwrap(), 1);
        assert_eq!(ledger.strike(&membership("1:8")).unwrap(), 1);
        assert_eq!(ledger.tracked_subjects(), 3);
    }
}
