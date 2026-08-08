#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    Blocked,
    Degraded,
}

impl AlertKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertKind::Blocked => "blocked",
            AlertKind::Degraded => "degraded",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub transport: String,
    pub kind: AlertKind,
    pub latency_ms: f64,
    pub average_ms: f64,
    pub timestamp: f64,
}

impl Alert {
    pub fn blocked(transport: &str, timestamp: f64) -> Alert {
        Alert {
            transport: transport.to_owned(),
            kind: AlertKind::Blocked,
            latency_ms: -1.0,
            average_ms: -1.0,
            timestamp,
        }
    }

    pub fn degraded(transport: &str, latency_ms: f64, average_ms: f64, timestamp: f64) -> Alert {
        Alert {
            transport: transport.to_owned(),
            kind: AlertKind::Degraded,
            latency_ms,
            average_ms,
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Alert, AlertKind};

    #[test]
    fn a_block_carries_no_measurement_because_there_was_none() {
        let alert = Alert::blocked("tor", 100.0);
        assert_eq!(alert.kind, AlertKind::Blocked);
        assert_eq!(alert.latency_ms, -1.0);
        assert_eq!(alert.average_ms, -1.0);
    }

    #[test]
    fn a_slowdown_carries_both_the_measurement_and_what_it_is_compared_against() {
        let alert = Alert::degraded("sse", 900.0, 15.0, 100.0);
        assert_eq!(alert.kind, AlertKind::Degraded);
        assert_eq!(alert.latency_ms, 900.0);
        assert_eq!(alert.average_ms, 15.0);
    }

    #[test]
    fn the_kind_is_named_the_way_the_status_reports_it() {
        assert_eq!(AlertKind::Blocked.as_str(), "blocked");
        assert_eq!(AlertKind::Degraded.as_str(), "degraded");
    }
}
