use crate::active_probe::signal::kind::Signal;

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    signals: Vec<Signal>,
    is_probe: bool,
}

impl Verdict {
    pub fn of(signals: Vec<Signal>, enough: usize) -> Self {
        let is_probe = enough > 0 && signals.len() >= enough;
        Verdict { signals, is_probe }
    }

    pub fn allowed() -> Self {
        Verdict {
            signals: Vec::new(),
            is_probe: false,
        }
    }

    pub fn is_probe(&self) -> bool {
        self.is_probe
    }

    pub fn signals(&self) -> &[Signal] {
        &self.signals
    }

    pub fn reason(&self) -> String {
        self.signals
            .iter()
            .map(Signal::to_string)
            .collect::<Vec<String>>()
            .join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict;
    use crate::active_probe::signal::kind::Signal;

    #[test]
    fn one_signal_is_not_a_verdict() {
        let verdict = Verdict::of(vec![Signal::NoCookies], 2);
        assert!(!verdict.is_probe());
        assert_eq!(verdict.reason(), "no_cookies");
    }

    #[test]
    fn enough_signals_are_a_verdict() {
        let verdict = Verdict::of(vec![Signal::NoCookies, Signal::NoUserAgent], 2);
        assert!(verdict.is_probe());
        assert_eq!(verdict.reason(), "no_cookies; no_user_agent");
    }

    #[test]
    fn a_request_nobody_looked_at_raises_nothing() {
        let verdict = Verdict::allowed();
        assert!(!verdict.is_probe());
        assert!(verdict.signals().is_empty());
        assert_eq!(verdict.reason(), "");
    }

    #[test]
    fn a_threshold_of_zero_does_not_turn_every_request_into_a_probe() {
        assert!(!Verdict::of(Vec::new(), 0).is_probe());
        assert!(!Verdict::of(vec![Signal::NoCookies], 0).is_probe());
    }
}
