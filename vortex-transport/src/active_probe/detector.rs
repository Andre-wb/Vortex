use std::sync::Arc;

use crate::active_probe::censor::networks::CensorNetworks;
use crate::active_probe::config::DetectorConfig;
use crate::active_probe::exempt::ExemptPaths;
use crate::active_probe::fingerprint;
use crate::active_probe::request::head::RequestHead;
use crate::active_probe::signal::kind::Signal;
use crate::active_probe::signal::{accept, browser, cookie, user_agent};
use crate::active_probe::stats::{Counters, Stats};
use crate::active_probe::store::memory_roll::MemoryRoll;
use crate::active_probe::store::memory_sightings::MemorySightings;
use crate::active_probe::verdict::Verdict;
use crate::ports::probe_roll::ProbeRoll;
use crate::ports::probe_sightings::ProbeSightings;

pub struct ActiveProbeDetector {
    config: DetectorConfig,
    networks: CensorNetworks,
    exempt: ExemptPaths,
    sightings: Arc<dyn ProbeSightings>,
    roll: Arc<dyn ProbeRoll>,
    counters: Counters,
}

impl Default for ActiveProbeDetector {
    fn default() -> Self {
        ActiveProbeDetector::new(DetectorConfig::default())
    }
}

impl ActiveProbeDetector {
    pub fn new(config: DetectorConfig) -> Self {
        let sightings = Arc::new(MemorySightings::new(
            config.max_tracked_requests,
            config.request_memory,
        ));
        let roll = Arc::new(MemoryRoll::new(
            config.max_tracked_probes,
            config.probe_memory,
        ));
        ActiveProbeDetector::with_stores(config, sightings, roll)
    }

    pub fn with_stores(
        config: DetectorConfig,
        sightings: Arc<dyn ProbeSightings>,
        roll: Arc<dyn ProbeRoll>,
    ) -> Self {
        ActiveProbeDetector {
            config,
            networks: CensorNetworks::default(),
            exempt: ExemptPaths::default(),
            sightings,
            roll,
            counters: Counters::default(),
        }
    }

    pub fn with_networks(mut self, networks: CensorNetworks) -> Self {
        self.networks = networks;
        self
    }

    pub fn with_exempt_paths(mut self, exempt: ExemptPaths) -> Self {
        self.exempt = exempt;
        self
    }

    pub fn config(&self) -> DetectorConfig {
        self.config
    }

    pub fn inspect(&self, request: &RequestHead, now: f64) -> Verdict {
        self.counters.inspected();
        if request.is_local() || self.exempt.covers(request.path()) {
            return Verdict::allowed();
        }

        let verdict = Verdict::of(self.signals(request, now), self.config.signals_for_verdict);
        if verdict.is_probe() {
            self.counters.detected();
            self.roll.record(request.peer(), now);
        }
        verdict
    }

    pub fn holds(&self, peer: &str) -> bool {
        self.roll.holds(peer)
    }

    pub fn forget_stale(&self, now: f64) {
        self.sightings
            .forget_stale(now - self.config.request_memory);
        self.roll.forget_stale(now - self.config.probe_memory);
    }

    pub fn stats(&self) -> Stats {
        Stats {
            total_probes_detected: self.counters.total_detected(),
            total_requests_inspected: self.counters.total_inspected(),
            known_probe_ips: self.roll.len(),
            fingerprint_cache_size: self.sightings.len(),
        }
    }

    fn signals(&self, request: &RequestHead, now: f64) -> Vec<Signal> {
        let mut signals = Vec::new();

        if let Some(address) = request.address() {
            if let Some(network) = self.networks.holding(&address) {
                signals.push(Signal::CensorNetwork(network));
            }
        }

        if let Some(signal) =
            browser::read(request.headers(), self.config.missing_headers_for_signal)
        {
            signals.push(signal);
        }

        if let Some(signal) = user_agent::read(request.user_agent(), self.config.short_user_agent) {
            signals.push(signal);
        }

        if let Some(signal) = self.replay(request, now) {
            signals.push(signal);
        }

        if let Some(signal) = cookie::read(request) {
            signals.push(signal);
        }

        if let Some(signal) = accept::read(request.path(), request.accept()) {
            signals.push(signal);
        }

        signals
    }

    fn replay(&self, request: &RequestHead, now: f64) -> Option<Signal> {
        let before = self.sightings.remember(&fingerprint::of(request), now)?;
        let elapsed = now - before;
        if (0.0..self.config.replay_window).contains(&elapsed) {
            return Some(Signal::Replay(elapsed));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ActiveProbeDetector;
    use crate::active_probe::censor::networks::CensorNetworks;
    use crate::active_probe::config::DetectorConfig;
    use crate::active_probe::exempt::ExemptPaths;
    use crate::active_probe::request::head::RequestHead;
    use crate::active_probe::request::headers::HeaderSet;
    use crate::active_probe::signal::browser::ALWAYS_SENT;
    use crate::active_probe::signal::kind::Signal;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    fn browser_headers() -> HeaderSet {
        let mut headers = HeaderSet::of(ALWAYS_SENT.map(|name| (name, "x")));
        headers.put("user-agent", CHROME);
        headers.put("cookie", "session=1");
        headers.put("accept", "*/*");
        headers
    }

    fn machine_headers() -> HeaderSet {
        HeaderSet::of([
            ("host", "example.org"),
            ("accept", "*/*"),
            ("accept-encoding", "gzip, deflate"),
            ("connection", "keep-alive"),
            ("user-agent", "python-httpx/0.28.1"),
        ])
    }

    fn request(peer: &str, path: &str, headers: HeaderSet) -> RequestHead {
        RequestHead::new(peer, "GET", path, headers)
    }

    #[test]
    fn a_browser_going_about_its_business_is_never_a_probe() {
        let detector = ActiveProbeDetector::default();
        let verdict = detector.inspect(
            &request("203.0.113.7", "/api/chats", browser_headers()),
            1000.0,
        );
        assert!(!verdict.is_probe(), "{}", verdict.reason());
    }

    #[test]
    fn a_scanner_with_nothing_a_browser_sends_is_a_probe() {
        let detector = ActiveProbeDetector::default();
        let bare = HeaderSet::of([("user-agent", "sqlmap/1.7.11#stable (https://sqlmap.org)")]);
        let verdict = detector.inspect(&request("203.0.113.7", "/api/chats", bare), 1000.0);
        assert!(verdict.is_probe());
        assert!(detector.holds("203.0.113.7"));
        assert_eq!(detector.stats().total_probes_detected, 1);
    }

    #[test]
    fn a_remote_node_probing_our_health_route_is_not_taken_for_a_censor() {
        let detector = ActiveProbeDetector::default();
        let verdict = detector.inspect(
            &request("203.0.113.7", "/health", machine_headers()),
            1000.0,
        );
        assert!(!verdict.is_probe(), "{}", verdict.reason());
        assert!(!detector.holds("203.0.113.7"));
    }

    #[test]
    fn the_same_machine_client_on_a_route_that_is_not_exempt_is_still_read_as_a_probe() {
        let detector = ActiveProbeDetector::default();
        let verdict = detector.inspect(
            &request("203.0.113.7", "/api/chats", machine_headers()),
            1000.0,
        );
        assert!(verdict.is_probe());
    }

    #[test]
    fn a_client_on_this_machine_is_never_inspected() {
        let detector = ActiveProbeDetector::default();
        let bare = HeaderSet::default();
        assert!(!detector
            .inspect(&request("127.0.0.1", "/api/chats", bare.clone()), 1000.0)
            .is_probe());
        assert!(!detector
            .inspect(&request("192.168.1.4", "/api/chats", bare), 1000.0)
            .is_probe());
    }

    #[test]
    fn the_same_request_repeated_at_once_is_seen_as_a_replay_and_not_a_second_later() {
        let detector = ActiveProbeDetector::default();
        let asking = || request("203.0.113.7", "/api/chats", browser_headers());
        detector.inspect(&asking(), 1000.0);
        let quick = detector.inspect(&asking(), 1000.5);
        assert!(quick
            .signals()
            .iter()
            .any(|signal| matches!(signal, Signal::Replay(_))));
        let later = detector.inspect(&asking(), 1010.0);
        assert!(!later
            .signals()
            .iter()
            .any(|signal| matches!(signal, Signal::Replay(_))));
    }

    #[test]
    fn a_clock_that_steps_backwards_never_reads_as_a_replay() {
        let detector = ActiveProbeDetector::default();
        let asking = || request("203.0.113.7", "/api/chats", browser_headers());
        detector.inspect(&asking(), 1000.0);
        let stepped_back = detector.inspect(&asking(), 900.0);
        assert!(!stepped_back
            .signals()
            .iter()
            .any(|signal| matches!(signal, Signal::Replay(_))));
    }

    #[test]
    fn an_address_in_a_suspected_network_still_needs_a_second_signal() {
        let detector = ActiveProbeDetector::default();
        let verdict = detector.inspect(
            &request("109.124.1.1", "/api/chats", browser_headers()),
            1000.0,
        );
        assert_eq!(verdict.signals().len(), 1);
        assert!(!verdict.is_probe());
    }

    #[test]
    fn a_telegram_address_raises_no_signal_at_all() {
        let detector = ActiveProbeDetector::default();
        let verdict = detector.inspect(
            &request("149.154.167.99", "/api/chats", browser_headers()),
            1000.0,
        );
        assert!(verdict.signals().is_empty(), "{}", verdict.reason());
    }

    #[test]
    fn a_detector_told_to_exempt_nothing_reads_the_health_route_like_any_other() {
        let detector = ActiveProbeDetector::default().with_exempt_paths(ExemptPaths::none());
        let verdict = detector.inspect(
            &request("203.0.113.7", "/health", machine_headers()),
            1000.0,
        );
        assert!(verdict.is_probe());
    }

    #[test]
    fn a_detector_with_no_suspected_networks_judges_only_by_the_request() {
        let detector = ActiveProbeDetector::default().with_networks(CensorNetworks::empty());
        let verdict = detector.inspect(
            &request("109.124.1.1", "/api/chats", browser_headers()),
            1000.0,
        );
        assert!(verdict.signals().is_empty());
    }

    #[test]
    fn every_request_is_counted_even_the_ones_that_are_never_inspected() {
        let detector = ActiveProbeDetector::default();
        detector.inspect(
            &request("127.0.0.1", "/api/chats", HeaderSet::default()),
            1.0,
        );
        detector.inspect(&request("203.0.113.7", "/health", machine_headers()), 2.0);
        assert_eq!(detector.stats().total_requests_inspected, 2);
        assert_eq!(detector.stats().total_probes_detected, 0);
    }

    #[test]
    fn what_the_detector_remembers_is_dropped_when_it_is_told_to_forget() {
        let detector = ActiveProbeDetector::new(DetectorConfig::default().request_memory(60.0));
        let bare = HeaderSet::of([("user-agent", "sqlmap/1.7.11#stable (https://sqlmap.org)")]);
        detector.inspect(&request("203.0.113.7", "/api/chats", bare), 1000.0);
        assert_eq!(detector.stats().fingerprint_cache_size, 1);
        detector.forget_stale(2000.0);
        assert_eq!(detector.stats().fingerprint_cache_size, 0);
    }
}
