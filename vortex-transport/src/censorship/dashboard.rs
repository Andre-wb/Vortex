use std::sync::Arc;

use crate::censorship::blocked;
use crate::censorship::config::DashboardConfig;
use crate::censorship::recommendation;
use crate::censorship::refusal::Refusal;
use crate::censorship::region::Region;
use crate::censorship::report::Report;
use crate::censorship::store::memory_reports::MemoryReportStore;
use crate::ports::report_store::ReportStore;

#[derive(Debug, Clone, PartialEq)]
pub struct RegionStatus {
    pub region: String,
    pub total_reports: usize,
    pub blocked: Vec<&'static str>,
    pub last_report: Option<Report>,
    pub recommended: &'static str,
}

pub struct CensorshipDashboard {
    config: DashboardConfig,
    store: Arc<dyn ReportStore>,
}

impl CensorshipDashboard {
    pub fn new(config: DashboardConfig) -> Self {
        CensorshipDashboard {
            store: Arc::new(MemoryReportStore::new(config)),
            config,
        }
    }

    pub fn with_store(config: DashboardConfig, store: Arc<dyn ReportStore>) -> Self {
        CensorshipDashboard { config, store }
    }

    pub fn config(&self) -> &DashboardConfig {
        &self.config
    }

    pub fn submit(
        &self,
        region: &str,
        pairs: &[(String, bool)],
        now: f64,
    ) -> Result<&'static str, Refusal> {
        let region = Region::parse(region).ok_or(Refusal::Region)?;
        let report = Report::of(pairs, now).ok_or(Refusal::NoTransports)?;
        self.store.submit(&region, &report)?;
        Ok(self.recommended_for(&region))
    }

    pub fn blocked(&self, region: &str) -> Vec<&'static str> {
        match Region::parse(region) {
            Some(region) => blocked::of(&self.store.reports(&region), &self.config),
            None => Vec::new(),
        }
    }

    pub fn recommended(&self, region: &str) -> &'static str {
        match Region::parse(region) {
            Some(region) => self.recommended_for(&region),
            None => recommendation::of(&[]),
        }
    }

    pub fn status(&self, region: &str) -> Option<RegionStatus> {
        let region = Region::parse(region)?;
        Some(self.status_of(&region))
    }

    pub fn all_regions(&self) -> Vec<RegionStatus> {
        self.store
            .regions()
            .iter()
            .map(|region| self.status_of(region))
            .collect()
    }

    pub fn regions(&self) -> usize {
        self.store.len()
    }

    fn status_of(&self, region: &Region) -> RegionStatus {
        let reports = self.store.reports(region);
        let blocked = blocked::of(&reports, &self.config);
        RegionStatus {
            region: region.as_str().to_owned(),
            total_reports: reports.len(),
            recommended: recommendation::of(&blocked),
            blocked,
            last_report: reports.last().cloned(),
        }
    }

    fn recommended_for(&self, region: &Region) -> &'static str {
        recommendation::of(&blocked::of(&self.store.reports(region), &self.config))
    }
}

impl Default for CensorshipDashboard {
    fn default() -> Self {
        CensorshipDashboard::new(DashboardConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::CensorshipDashboard;
    use crate::censorship::config::DashboardConfig;
    use crate::censorship::refusal::Refusal;

    fn pairs(items: &[(&str, bool)]) -> Vec<(String, bool)> {
        items
            .iter()
            .map(|(name, ok)| ((*name).to_owned(), *ok))
            .collect()
    }

    #[test]
    fn a_report_from_a_region_nobody_can_name_is_refused() {
        let dashboard = CensorshipDashboard::default();
        let report = pairs(&[("tor", true)]);
        assert_eq!(
            dashboard.submit("ru ru", &report, 1.0),
            Err(Refusal::Region)
        );
        assert_eq!(dashboard.submit("", &report, 1.0), Err(Refusal::Region));
        assert_eq!(dashboard.regions(), 0);
    }

    #[test]
    fn a_report_about_nothing_known_is_refused_and_stores_nothing() {
        let dashboard = CensorshipDashboard::default();
        assert_eq!(
            dashboard.submit("ru", &pairs(&[("vmess", false)]), 1.0),
            Err(Refusal::NoTransports)
        );
        assert_eq!(dashboard.regions(), 0);
    }

    #[test]
    fn a_region_that_reaches_everything_is_told_to_use_the_flagship() {
        let dashboard = CensorshipDashboard::default();
        let recommended = dashboard.submit("ru", &pairs(&[("reality", true)]), 1.0);
        assert_eq!(recommended, Ok("reality"));
    }

    #[test]
    fn a_quorum_of_reports_moves_the_region_off_a_blocked_transport() {
        let dashboard = CensorshipDashboard::default();
        let report = pairs(&[("reality", false)]);
        assert_eq!(dashboard.submit("ru", &report, 1.0), Ok("reality"));
        assert_eq!(dashboard.submit("ru", &report, 2.0), Ok("reality"));
        assert_eq!(dashboard.submit("ru", &report, 3.0), Ok("direct_https"));
    }

    #[test]
    fn one_region_never_decides_for_another() {
        let dashboard = CensorshipDashboard::default();
        for tick in 0..3 {
            dashboard
                .submit("ru", &pairs(&[("reality", false)]), tick as f64)
                .unwrap();
        }
        assert_eq!(dashboard.recommended("ru"), "direct_https");
        assert_eq!(dashboard.recommended("ir"), "reality");
        assert_eq!(dashboard.regions(), 1);
    }

    #[test]
    fn a_region_written_in_another_case_is_the_same_region() {
        let dashboard = CensorshipDashboard::default();
        for tick in 0..3 {
            dashboard
                .submit("RU", &pairs(&[("reality", false)]), tick as f64)
                .unwrap();
        }
        assert_eq!(dashboard.recommended("ru"), "direct_https");
        assert_eq!(dashboard.regions(), 1);
    }

    #[test]
    fn the_status_of_a_region_holds_only_what_the_domain_understands() {
        let dashboard = CensorshipDashboard::default();
        dashboard
            .submit("ru", &pairs(&[("tor", false), ("vmess", true)]), 7.0)
            .unwrap();
        let status = dashboard.status("ru").unwrap();
        assert_eq!(status.region, "ru");
        assert_eq!(status.total_reports, 1);
        let last = status.last_report.unwrap();
        assert_eq!(last.received_at, 7.0);
        assert_eq!(last.verdicts.len(), 1);
        assert_eq!(last.says("tor"), Some(false));
    }

    #[test]
    fn a_region_nobody_reported_has_no_status_but_still_has_a_recommendation() {
        let dashboard = CensorshipDashboard::default();
        assert_eq!(dashboard.status("ru").unwrap().total_reports, 0);
        assert_eq!(dashboard.status("ru ru"), None);
        assert_eq!(dashboard.recommended("ru ru"), "reality");
        assert!(dashboard.blocked("ru ru").is_empty());
    }

    #[test]
    fn the_panel_refuses_a_new_region_once_it_is_full() {
        let dashboard = CensorshipDashboard::new(DashboardConfig::default().max_regions(1));
        dashboard
            .submit("ru", &pairs(&[("tor", true)]), 1.0)
            .unwrap();
        assert_eq!(
            dashboard.submit("ir", &pairs(&[("tor", true)]), 1.0),
            Err(Refusal::AtCapacity)
        );
        assert_eq!(dashboard.regions(), 1);
    }

    #[test]
    fn every_region_that_reported_appears_in_the_map() {
        let dashboard = CensorshipDashboard::default();
        for name in ["ru", "ir"] {
            dashboard
                .submit(name, &pairs(&[("tor", true)]), 1.0)
                .unwrap();
        }
        let regions: Vec<String> = dashboard
            .all_regions()
            .into_iter()
            .map(|status| status.region)
            .collect();
        assert_eq!(regions, vec!["ir", "ru"]);
    }
}
