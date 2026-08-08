use std::sync::{Arc, RwLock};

use crate::ports::random_source::RandomSource;
use crate::probe::catalogue;
use crate::probe::config::ProbeConfig;
use crate::probe::outcome::Outcome;
use crate::probe::results::Results;
use crate::probe::schedule::Schedule;
use crate::probe::selection;
use crate::probe::target::{self, Target};
use crate::probe::token::ProbeToken;
use crate::random::os_random::OsRandom;

pub struct CensorshipProbe {
    config: ProbeConfig,
    random: Arc<dyn RandomSource>,
    state: RwLock<State>,
}

struct State {
    results: Results,
    schedule: Schedule,
    best: Option<&'static str>,
}

impl CensorshipProbe {
    pub fn new(config: ProbeConfig, random: Arc<dyn RandomSource>) -> Self {
        let schedule = Schedule::new(&config, random.as_ref());
        CensorshipProbe {
            config,
            random,
            state: RwLock::new(State {
                results: Results::new(),
                schedule,
                best: None,
            }),
        }
    }

    pub fn config(&self) -> &ProbeConfig {
        &self.config
    }

    pub fn plan(&self) -> Vec<Target> {
        target::all()
    }

    pub fn timeout_of(&self, name: &str) -> Option<f64> {
        catalogue::by_name(name).map(|probe| probe.timeout_secs)
    }

    pub fn read(&self, name: &str, status: u16, latency_ms: i64) -> Option<Outcome> {
        catalogue::by_name(name).map(|probe| Outcome::answered(probe, status, latency_ms))
    }

    pub fn record(&self, name: &str, outcome: Outcome) -> bool {
        self.state.write().unwrap().results.record(name, outcome)
    }

    pub fn finish(&self, now: f64) -> Option<&'static str> {
        let mut state = self.state.write().unwrap();
        state.best = selection::best(&state.results);
        state
            .schedule
            .record_run(now, &self.config, self.random.as_ref());
        state.best
    }

    pub fn best(&self) -> Option<&'static str> {
        self.state.read().unwrap().best
    }

    pub fn due(&self, now: f64) -> bool {
        self.state.read().unwrap().schedule.due(now)
    }

    pub fn interval_secs(&self) -> f64 {
        self.state.read().unwrap().schedule.interval_secs()
    }

    pub fn last_run(&self) -> Option<f64> {
        self.state.read().unwrap().schedule.last_run()
    }

    pub fn results(&self) -> Results {
        self.state.read().unwrap().results.clone()
    }

    pub fn serves(&self, token: &str) -> Option<&'static str> {
        let token = ProbeToken::parse(token)?;
        catalogue::by_token(&token).map(|probe| probe.name)
    }
}

impl Default for CensorshipProbe {
    fn default() -> Self {
        CensorshipProbe::new(ProbeConfig::default(), Arc::new(OsRandom::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::CensorshipProbe;
    use crate::probe::outcome::Outcome;

    fn answered(probe: &CensorshipProbe, name: &str, status: u16) {
        let outcome = probe.read(name, status, 7).unwrap();
        assert!(probe.record(name, outcome));
    }

    #[test]
    fn a_probe_that_has_not_run_recommends_nothing() {
        let probe = CensorshipProbe::default();
        assert_eq!(probe.best(), None);
        assert_eq!(probe.last_run(), None);
        assert!(probe.due(0.0));
    }

    #[test]
    fn the_verdict_appears_only_when_the_run_is_finished() {
        let probe = CensorshipProbe::default();
        answered(&probe, "tor", 200);
        assert_eq!(probe.best(), None, "запись ответа сама по себе не решение");
        assert_eq!(probe.finish(100.0), Some("tor"));
        assert_eq!(probe.best(), Some("tor"));
    }

    #[test]
    fn a_finished_run_is_not_due_again_at_once() {
        let probe = CensorshipProbe::default();
        probe.finish(100.0);
        assert!(!probe.due(100.0));
        assert!(probe.due(100.0 + probe.interval_secs() + 1.0));
        assert_eq!(probe.last_run(), Some(100.0));
    }

    #[test]
    fn a_run_where_the_server_answered_nothing_recommends_nothing() {
        let probe = CensorshipProbe::default();
        for target in probe.plan() {
            probe.record(target.name, Outcome::timed_out());
        }
        assert_eq!(probe.finish(100.0), None);
    }

    #[test]
    fn a_token_the_catalogue_issued_names_its_transport() {
        let probe = CensorshipProbe::default();
        assert_eq!(probe.serves("d7ac1d220e6a"), Some("reality"));
    }

    #[test]
    fn a_token_nobody_issued_names_nothing() {
        let probe = CensorshipProbe::default();
        assert_eq!(probe.serves("000000000000"), None);
        assert_eq!(probe.serves("zz"), None);
        assert_eq!(probe.serves(""), None);
    }

    #[test]
    fn a_transport_outside_the_catalogue_is_never_recorded_or_timed() {
        let probe = CensorshipProbe::default();
        assert_eq!(probe.timeout_of("vmess"), None);
        assert!(probe.read("vmess", 200, 1).is_none());
        assert!(!probe.record("vmess", Outcome::timed_out()));
    }

    #[test]
    fn every_probe_of_the_plan_is_given_a_deadline_of_its_own() {
        let probe = CensorshipProbe::default();
        for target in probe.plan() {
            assert!(probe.timeout_of(target.name).unwrap() > 0.0);
        }
    }
}
