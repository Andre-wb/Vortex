use crate::probe::kind::ProbeKind;
use crate::probe::token::ProbeToken;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Probe {
    pub name: &'static str,
    pub priority: u8,
    pub timeout_secs: f64,
    pub kind: ProbeKind,
}

impl Probe {
    pub const fn new(name: &'static str, priority: u8, timeout_secs: f64, kind: ProbeKind) -> Self {
        Probe {
            name,
            priority,
            timeout_secs,
            kind,
        }
    }

    pub fn token(&self) -> ProbeToken {
        ProbeToken::derive(self.name)
    }

    pub fn accepts(&self, status: u16) -> bool {
        self.kind.accepts(status)
    }
}

#[cfg(test)]
mod tests {
    use super::Probe;
    use crate::probe::kind::ProbeKind;
    use crate::probe::token::ProbeToken;

    #[test]
    fn a_probe_carries_the_token_of_its_own_name() {
        let probe = Probe::new("reality", 1, 8.0, ProbeKind::Token);
        assert_eq!(probe.token(), ProbeToken::derive("reality"));
    }

    #[test]
    fn a_probe_reads_answers_the_way_its_kind_does() {
        let probe = Probe::new("direct_https", 2, 5.0, ProbeKind::Health);
        assert!(probe.accepts(401));
        assert!(!probe.accepts(404));
    }
}
