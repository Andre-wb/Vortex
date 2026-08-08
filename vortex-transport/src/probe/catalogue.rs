use crate::probe::entry::Probe;
use crate::probe::kind::ProbeKind;
use crate::probe::token::ProbeToken;

pub const PROBES: &[Probe] = &[
    Probe::new("reality", 1, 8.0, ProbeKind::Token),
    Probe::new("direct_https", 2, 5.0, ProbeKind::Health),
    Probe::new("websocket", 3, 5.0, ProbeKind::WebSocket),
    Probe::new("sse", 4, 8.0, ProbeKind::Sse),
    Probe::new("trojan", 5, 10.0, ProbeKind::Token),
    Probe::new("shadowtls", 6, 10.0, ProbeKind::Token),
    Probe::new("cdn_relay", 7, 10.0, ProbeKind::Token),
    Probe::new("meek_cdn", 8, 15.0, ProbeKind::Token),
    Probe::new("doh_tunnel", 9, 15.0, ProbeKind::Token),
    Probe::new("tor", 10, 30.0, ProbeKind::Token),
];

pub fn by_name(name: &str) -> Option<&'static Probe> {
    PROBES.iter().find(|probe| probe.name == name)
}

pub fn by_token(token: &ProbeToken) -> Option<&'static Probe> {
    PROBES.iter().find(|probe| probe.token() == *token)
}

pub fn names() -> Vec<&'static str> {
    PROBES.iter().map(|probe| probe.name).collect()
}

#[cfg(test)]
mod tests {
    use super::{by_name, by_token, names, PROBES};
    use crate::probe::kind::ProbeKind;
    use crate::probe::token::ProbeToken;
    use std::collections::HashSet;

    #[test]
    fn the_table_is_written_in_the_order_it_is_read() {
        let priorities: Vec<u8> = PROBES.iter().map(|probe| probe.priority).collect();
        let mut sorted = priorities.clone();
        sorted.sort_unstable();
        assert_eq!(
            priorities, sorted,
            "порядок выбора задаётся порядком таблицы"
        );
    }

    #[test]
    fn no_two_transports_share_a_name_a_priority_or_a_token() {
        let names: HashSet<&str> = PROBES.iter().map(|probe| probe.name).collect();
        let priorities: HashSet<u8> = PROBES.iter().map(|probe| probe.priority).collect();
        let tokens: HashSet<String> = PROBES.iter().map(|probe| probe.token().to_hex()).collect();
        assert_eq!(names.len(), PROBES.len());
        assert_eq!(priorities.len(), PROBES.len());
        assert_eq!(tokens.len(), PROBES.len());
    }

    #[test]
    fn a_transport_is_found_by_the_name_it_was_written_under() {
        assert_eq!(by_name("tor").map(|probe| probe.priority), Some(10));
        assert_eq!(by_name("Tor"), None);
        assert_eq!(by_name("nothing"), None);
    }

    #[test]
    fn a_token_leads_back_to_the_transport_that_produced_it() {
        let probe = by_name("shadowtls").unwrap();
        assert_eq!(
            by_token(&probe.token()).map(|found| found.name),
            Some("shadowtls")
        );
    }

    #[test]
    fn a_token_nobody_issued_leads_nowhere() {
        assert_eq!(by_token(&ProbeToken::parse("000000000000").unwrap()), None);
    }

    #[test]
    fn only_the_three_reachability_checks_are_not_token_probes() {
        let over_http: Vec<&str> = PROBES
            .iter()
            .filter(|probe| probe.kind != ProbeKind::Token)
            .map(|probe| probe.name)
            .collect();
        assert_eq!(over_http, vec!["direct_https", "websocket", "sse"]);
    }

    #[test]
    fn every_transport_the_dashboard_knows_can_be_probed() {
        assert_eq!(names().len(), PROBES.len());
    }
}
