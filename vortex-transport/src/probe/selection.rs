use crate::probe::catalogue::PROBES;
use crate::probe::results::Results;

pub fn best(results: &Results) -> Option<&'static str> {
    PROBES
        .iter()
        .find(|probe| results.is_ok(probe.name))
        .map(|probe| probe.name)
}

#[cfg(test)]
mod tests {
    use super::best;
    use crate::probe::catalogue::by_name;
    use crate::probe::outcome::Outcome;
    use crate::probe::results::Results;

    fn results(working: &[&str]) -> Results {
        let mut results = Results::new();
        for probe in crate::probe::catalogue::PROBES {
            let outcome = if working.contains(&probe.name) {
                Outcome::answered(by_name(probe.name).unwrap(), 200, 5)
            } else {
                Outcome::timed_out()
            };
            results.record(probe.name, outcome);
        }
        results
    }

    #[test]
    fn the_working_transport_of_the_highest_priority_wins() {
        assert_eq!(best(&results(&["reality", "tor"])), Some("reality"));
        assert_eq!(best(&results(&["tor", "sse"])), Some("sse"));
        assert_eq!(best(&results(&["tor"])), Some("tor"));
    }

    #[test]
    fn a_run_where_nothing_answered_chooses_nothing() {
        assert_eq!(best(&results(&[])), None);
        assert_eq!(best(&Results::new()), None);
    }

    #[test]
    fn the_choice_does_not_depend_on_the_order_the_answers_arrived_in() {
        let mut forwards = Results::new();
        forwards.record("tor", Outcome::answered(by_name("tor").unwrap(), 200, 5));
        forwards.record("sse", Outcome::answered(by_name("sse").unwrap(), 200, 5));

        let mut backwards = Results::new();
        backwards.record("sse", Outcome::answered(by_name("sse").unwrap(), 200, 5));
        backwards.record("tor", Outcome::answered(by_name("tor").unwrap(), 200, 5));

        assert_eq!(best(&forwards), best(&backwards));
        assert_eq!(best(&forwards), Some("sse"));
    }
}
