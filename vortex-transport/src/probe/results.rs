use crate::probe::catalogue;
use crate::probe::outcome::Outcome;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Results {
    entries: Vec<(&'static str, Outcome)>,
}

impl Results {
    pub fn new() -> Self {
        Results {
            entries: Vec::new(),
        }
    }

    pub fn record(&mut self, name: &str, outcome: Outcome) -> bool {
        let Some(probe) = catalogue::by_name(name) else {
            return false;
        };
        match self
            .entries
            .iter_mut()
            .find(|(known, _)| *known == probe.name)
        {
            Some(entry) => entry.1 = outcome,
            None => self.entries.push((probe.name, outcome)),
        }
        true
    }

    pub fn get(&self, name: &str) -> Option<&Outcome> {
        self.entries
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, outcome)| outcome)
    }

    pub fn is_ok(&self, name: &str) -> bool {
        self.get(name).map(|outcome| outcome.ok).unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &Outcome)> {
        self.entries.iter().map(|(name, outcome)| (*name, outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::Results;
    use crate::probe::catalogue::by_name;
    use crate::probe::outcome::Outcome;

    fn ok_of(name: &str) -> Outcome {
        Outcome::answered(by_name(name).unwrap(), 200, 5)
    }

    #[test]
    fn a_recorded_transport_is_read_back_under_its_own_name() {
        let mut results = Results::new();
        assert!(results.record("tor", ok_of("tor")));
        assert!(results.is_ok("tor"));
        assert!(!results.is_ok("reality"));
    }

    #[test]
    fn a_transport_nobody_probes_is_never_recorded() {
        let mut results = Results::new();
        assert!(!results.record("vmess", ok_of("tor")));
        assert!(results.is_empty());
    }

    #[test]
    fn a_second_run_replaces_the_verdict_of_the_first() {
        let mut results = Results::new();
        results.record("tor", ok_of("tor"));
        results.record("tor", Outcome::timed_out());
        assert_eq!(results.len(), 1);
        assert!(!results.is_ok("tor"));
    }

    #[test]
    fn a_transport_that_was_never_probed_is_not_a_working_one() {
        assert!(!Results::new().is_ok("reality"));
    }
}
