use crate::probe::entry::Probe;

pub const NO_LATENCY: i64 = -1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub latency_ms: i64,
    pub status: Option<u16>,
    pub error: Option<String>,
}

impl Outcome {
    pub fn answered(probe: &Probe, status: u16, latency_ms: i64) -> Outcome {
        Outcome {
            ok: probe.accepts(status),
            latency_ms,
            status: Some(status),
            error: None,
        }
    }

    pub fn failed(error: &str, latency_ms: i64) -> Outcome {
        Outcome {
            ok: false,
            latency_ms,
            status: None,
            error: Some(error.to_owned()),
        }
    }

    pub fn timed_out() -> Outcome {
        Outcome::failed("timeout", NO_LATENCY)
    }
}

#[cfg(test)]
mod tests {
    use super::{Outcome, NO_LATENCY};
    use crate::probe::catalogue::by_name;

    #[test]
    fn an_answer_the_probe_accepts_is_a_working_transport() {
        let probe = by_name("direct_https").unwrap();
        let outcome = Outcome::answered(probe, 200, 12);
        assert!(outcome.ok);
        assert_eq!(outcome.status, Some(200));
        assert_eq!(outcome.error, None);
    }

    #[test]
    fn an_answer_from_a_route_that_is_not_there_is_not_a_working_transport() {
        let probe = by_name("reality").unwrap();
        assert!(!Outcome::answered(probe, 404, 12).ok);
    }

    #[test]
    fn a_probe_that_never_answered_carries_no_latency() {
        let outcome = Outcome::timed_out();
        assert!(!outcome.ok);
        assert_eq!(outcome.latency_ms, NO_LATENCY);
        assert_eq!(outcome.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn a_probe_that_broke_carries_the_reason_it_broke() {
        let outcome = Outcome::failed("connection refused", 3);
        assert!(!outcome.ok);
        assert_eq!(outcome.error.as_deref(), Some("connection refused"));
        assert_eq!(outcome.status, None);
    }
}
