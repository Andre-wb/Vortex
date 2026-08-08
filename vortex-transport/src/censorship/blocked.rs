use crate::censorship::config::DashboardConfig;
use crate::censorship::report::Report;
use crate::probe::catalogue::PROBES;

pub fn of(reports: &[Report], config: &DashboardConfig) -> Vec<&'static str> {
    PROBES
        .iter()
        .filter(|probe| is_blocked(probe.name, reports, config))
        .map(|probe| probe.name)
        .collect()
}

fn is_blocked(transport: &str, reports: &[Report], config: &DashboardConfig) -> bool {
    let mentions: Vec<bool> = reports
        .iter()
        .filter_map(|report| report.says(transport))
        .collect();
    if mentions.is_empty() || mentions.len() < config.reports_for_verdict {
        return false;
    }
    let against = mentions.iter().filter(|ok| !**ok).count() as f64;
    against / mentions.len() as f64 >= config.quorum_ratio
}

#[cfg(test)]
mod tests {
    use super::of;
    use crate::censorship::config::DashboardConfig;
    use crate::censorship::report::Report;

    fn report(items: &[(&str, bool)]) -> Report {
        let pairs: Vec<(String, bool)> = items
            .iter()
            .map(|(name, ok)| ((*name).to_owned(), *ok))
            .collect();
        Report::of(&pairs, 0.0).unwrap()
    }

    fn saying(times: usize, items: &[(&str, bool)]) -> Vec<Report> {
        (0..times).map(|_| report(items)).collect()
    }

    #[test]
    fn one_client_does_not_block_a_transport_for_a_whole_region() {
        let blocked = of(&saying(1, &[("tor", false)]), &DashboardConfig::default());
        assert!(blocked.is_empty());
    }

    #[test]
    fn a_quorum_of_clients_does() {
        let blocked = of(&saying(3, &[("tor", false)]), &DashboardConfig::default());
        assert_eq!(blocked, vec!["tor"]);
    }

    #[test]
    fn a_single_dissenting_client_does_not_unblock_what_the_others_reported() {
        let mut reports = saying(4, &[("tor", false)]);
        reports.push(report(&[("tor", true)]));
        assert_eq!(of(&reports, &DashboardConfig::default()), vec!["tor"]);
    }

    #[test]
    fn a_transport_the_majority_reaches_is_not_blocked() {
        let mut reports = saying(1, &[("tor", false)]);
        reports.extend(saying(3, &[("tor", true)]));
        assert!(of(&reports, &DashboardConfig::default()).is_empty());
    }

    #[test]
    fn a_transport_nobody_mentioned_is_never_blocked() {
        let blocked = of(&saying(5, &[("tor", false)]), &DashboardConfig::default());
        assert_eq!(blocked, vec!["tor"]);
        assert!(!blocked.contains(&"reality"));
    }

    #[test]
    fn the_blocked_transports_are_listed_in_the_order_of_the_catalogue() {
        let reports = saying(3, &[("tor", false), ("reality", false), ("sse", false)]);
        assert_eq!(
            of(&reports, &DashboardConfig::default()),
            vec!["reality", "sse", "tor"]
        );
    }

    #[test]
    fn a_region_without_reports_blocks_nothing() {
        assert!(of(&[], &DashboardConfig::default()).is_empty());
    }

    #[test]
    fn the_quorum_the_configuration_asks_for_is_the_one_applied() {
        let config = DashboardConfig::default()
            .reports_for_verdict(2)
            .quorum_ratio(1.0);
        let mut reports = saying(3, &[("tor", false)]);
        assert_eq!(of(&reports, &config), vec!["tor"]);
        reports.push(report(&[("tor", true)]));
        assert!(of(&reports, &config).is_empty());
    }
}
