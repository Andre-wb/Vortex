use crate::probe::catalogue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportVerdict {
    pub transport: &'static str,
    pub ok: bool,
}

impl TransportVerdict {
    pub fn parse(transport: &str, ok: bool) -> Option<TransportVerdict> {
        catalogue::by_name(transport).map(|probe| TransportVerdict {
            transport: probe.name,
            ok,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::TransportVerdict;

    #[test]
    fn a_verdict_about_a_known_transport_is_kept() {
        let verdict = TransportVerdict::parse("tor", false).unwrap();
        assert_eq!(verdict.transport, "tor");
        assert!(!verdict.ok);
    }

    #[test]
    fn a_verdict_about_anything_else_is_not_a_verdict() {
        assert_eq!(TransportVerdict::parse("vmess", true), None);
        assert_eq!(TransportVerdict::parse("", true), None);
        assert_eq!(TransportVerdict::parse("TOR", true), None);
        assert_eq!(TransportVerdict::parse("../etc", true), None);
    }

    #[test]
    fn the_name_kept_is_the_one_the_catalogue_owns() {
        let verdict = TransportVerdict::parse("reality", true).unwrap();
        assert!(std::ptr::eq(
            verdict.transport,
            crate::probe::catalogue::by_name("reality").unwrap().name
        ));
    }
}
