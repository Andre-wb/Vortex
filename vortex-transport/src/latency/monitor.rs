use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use crate::latency::alert::Alert;
use crate::latency::config::LatencyConfig;
use crate::latency::history::History;
use crate::latency::stats::Stats;
use crate::latency::verdict::{self, Verdict};
use crate::ports::random_source::RandomSource;
use crate::random::os_random::OsRandom;
use crate::random::sample::memoryless;

pub struct LatencyMonitor {
    config: LatencyConfig,
    random: Arc<dyn RandomSource>,
    state: RwLock<State>,
}

struct State {
    tracked: Vec<(String, History)>,
    alerts: VecDeque<Alert>,
}

impl LatencyMonitor {
    pub fn new(config: LatencyConfig, random: Arc<dyn RandomSource>) -> Self {
        LatencyMonitor {
            config,
            random,
            state: RwLock::new(State {
                tracked: Vec::new(),
                alerts: VecDeque::new(),
            }),
        }
    }

    pub fn config(&self) -> &LatencyConfig {
        &self.config
    }

    pub fn record(&self, transport: &str, latency_ms: f64, now: f64) -> Verdict {
        let mut state = self.state.write().unwrap();
        let position = match state.tracked.iter().position(|(name, _)| name == transport) {
            Some(position) => position,
            None => {
                state
                    .tracked
                    .push((transport.to_owned(), History::new(self.config.history_len)));
                state.tracked.len() - 1
            }
        };

        let history = &mut state.tracked[position].1;
        history.push(latency_ms);
        let samples = history.samples();
        let verdict = verdict::of(&samples, &self.config);
        let announce = history.remember_blocked(verdict == Verdict::Blocked);

        match verdict {
            Verdict::Blocked if announce => {
                let alert = Alert::blocked(transport, now);
                push_alert(&mut state, alert, self.config.alert_history_len);
            }
            Verdict::Degraded => {
                let alert = Alert::degraded(
                    transport,
                    latency_ms,
                    verdict::average_before_last(&samples),
                    now,
                );
                push_alert(&mut state, alert, self.config.alert_history_len);
            }
            _ => {}
        }
        verdict
    }

    pub fn next_wait(&self) -> f64 {
        memoryless::delay(
            self.config.probe_interval_secs,
            self.config.jitter_low,
            self.config.jitter_high,
            self.random.as_ref(),
        )
    }

    pub fn stats(&self, transport: &str) -> Option<Stats> {
        self.state
            .read()
            .unwrap()
            .tracked
            .iter()
            .find(|(name, _)| name == transport)
            .map(|(_, history)| history.stats())
    }

    pub fn all_stats(&self) -> Vec<(String, Stats)> {
        self.state
            .read()
            .unwrap()
            .tracked
            .iter()
            .map(|(name, history)| (name.clone(), history.stats()))
            .collect()
    }

    pub fn tracked(&self) -> usize {
        self.state.read().unwrap().tracked.len()
    }

    pub fn recent_alerts(&self, limit: usize) -> Vec<Alert> {
        let state = self.state.read().unwrap();
        let skip = state.alerts.len().saturating_sub(limit);
        state.alerts.iter().skip(skip).cloned().collect()
    }
}

impl Default for LatencyMonitor {
    fn default() -> Self {
        LatencyMonitor::new(LatencyConfig::default(), Arc::new(OsRandom::new()))
    }
}

fn push_alert(state: &mut State, alert: Alert, limit: usize) {
    state.alerts.push_back(alert);
    while state.alerts.len() > limit.max(1) {
        state.alerts.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::LatencyMonitor;
    use crate::latency::alert::AlertKind;
    use crate::latency::config::LatencyConfig;
    use crate::latency::verdict::Verdict;
    use crate::random::os_random::OsRandom;
    use std::sync::Arc;

    fn monitor() -> LatencyMonitor {
        LatencyMonitor::default()
    }

    #[test]
    fn a_transport_appears_the_first_time_it_is_measured() {
        let monitor = monitor();
        assert_eq!(monitor.tracked(), 0);
        monitor.record("tor", 40.0, 1.0);
        assert_eq!(monitor.tracked(), 1);
        assert_eq!(monitor.stats("tor").unwrap().total, 1);
    }

    #[test]
    fn three_failures_raise_one_alert_and_not_one_per_probe() {
        let monitor = monitor();
        for tick in 0..10 {
            monitor.record("tor", -1.0, tick as f64);
        }
        let alerts = monitor.recent_alerts(50);
        assert_eq!(alerts.len(), 1, "повторяющийся отказ — одно событие");
        assert_eq!(alerts[0].kind, AlertKind::Blocked);
    }

    #[test]
    fn a_transport_that_recovers_and_falls_again_is_reported_twice() {
        let monitor = monitor();
        for tick in 0..3 {
            monitor.record("tor", -1.0, tick as f64);
        }
        monitor.record("tor", 20.0, 4.0);
        for tick in 5..8 {
            monitor.record("tor", -1.0, tick as f64);
        }
        assert_eq!(monitor.recent_alerts(50).len(), 2);
    }

    #[test]
    fn a_slowdown_is_reported_with_what_it_was_compared_against() {
        let monitor = monitor();
        for tick in 0..6 {
            monitor.record("sse", 10.0, tick as f64);
        }
        assert_eq!(monitor.record("sse", 900.0, 7.0), Verdict::Degraded);
        let alerts = monitor.recent_alerts(5);
        assert_eq!(alerts.last().unwrap().kind, AlertKind::Degraded);
        assert_eq!(alerts.last().unwrap().average_ms, 10.0);
    }

    #[test]
    fn the_alert_log_never_grows_without_a_limit() {
        let monitor = LatencyMonitor::new(
            LatencyConfig::default().alert_history_len(3),
            Arc::new(OsRandom::new()),
        );
        for tick in 0..40 {
            let transport = format!("t{tick}");
            for step in 0..3 {
                monitor.record(&transport, -1.0, (tick * 3 + step) as f64);
            }
        }
        assert_eq!(monitor.recent_alerts(100).len(), 3);
    }

    #[test]
    fn transports_are_measured_apart_from_one_another() {
        let monitor = monitor();
        monitor.record("tor", 10.0, 1.0);
        monitor.record("sse", 50.0, 1.0);
        assert_eq!(monitor.stats("tor").unwrap().average, 10.0);
        assert_eq!(monitor.stats("sse").unwrap().average, 50.0);
        assert_eq!(monitor.all_stats().len(), 2);
        assert!(monitor.stats("reality").is_none());
    }

    #[test]
    fn the_wait_between_rounds_stays_inside_the_bounds_and_never_repeats() {
        let monitor = monitor();
        let config = monitor.config();
        let mut drawn = Vec::new();
        for _ in 0..200 {
            let wait = monitor.next_wait();
            assert!(wait >= config.shortest_interval());
            assert!(wait <= config.longest_interval());
            drawn.push(wait);
        }
        drawn.sort_by(|left, right| left.partial_cmp(right).unwrap());
        drawn.dedup();
        assert!(drawn.len() > 190);
    }
}
