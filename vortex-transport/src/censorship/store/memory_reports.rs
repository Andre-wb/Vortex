use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::RwLock;

use crate::censorship::config::DashboardConfig;
use crate::censorship::refusal::Refusal;
use crate::censorship::region::Region;
use crate::censorship::report::Report;
use crate::ports::report_store::ReportStore;

pub struct MemoryReportStore {
    config: DashboardConfig,
    regions: RwLock<BTreeMap<Region, VecDeque<Report>>>,
}

impl MemoryReportStore {
    pub fn new(config: DashboardConfig) -> Self {
        MemoryReportStore {
            config,
            regions: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Default for MemoryReportStore {
    fn default() -> Self {
        MemoryReportStore::new(DashboardConfig::default())
    }
}

impl ReportStore for MemoryReportStore {
    fn submit(&self, region: &Region, report: &Report) -> Result<(), Refusal> {
        let mut regions = self.regions.write().unwrap();
        if !regions.contains_key(region) && regions.len() >= self.config.max_regions {
            return Err(Refusal::AtCapacity);
        }
        let held = regions.entry(region.clone()).or_default();
        held.push_back(report.clone());
        while held.len() > self.config.max_reports_per_region.max(1) {
            held.pop_front();
        }
        Ok(())
    }

    fn reports(&self, region: &Region) -> Vec<Report> {
        self.regions
            .read()
            .unwrap()
            .get(region)
            .map(|held| held.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn regions(&self) -> Vec<Region> {
        self.regions.read().unwrap().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryReportStore;
    use crate::censorship::config::DashboardConfig;
    use crate::censorship::refusal::Refusal;
    use crate::censorship::region::Region;
    use crate::censorship::report::Report;
    use crate::ports::report_store::ReportStore;

    fn report(at: f64) -> Report {
        Report::of(&[("tor".to_owned(), false)], at).unwrap()
    }

    #[test]
    fn a_region_holds_no_more_reports_than_it_was_given_room_for() {
        let store = MemoryReportStore::new(DashboardConfig::default().max_reports_per_region(3));
        let region = Region::parse("ru").unwrap();
        for tick in 0..10 {
            store.submit(&region, &report(tick as f64)).unwrap();
        }
        let held = store.reports(&region);
        assert_eq!(held.len(), 3);
        assert_eq!(held[0].received_at, 7.0);
        assert_eq!(held[2].received_at, 9.0);
    }

    #[test]
    fn a_new_region_is_refused_once_the_panel_is_full_and_a_known_one_is_not() {
        let store = MemoryReportStore::new(DashboardConfig::default().max_regions(2));
        let first = Region::parse("ru").unwrap();
        let second = Region::parse("ir").unwrap();
        let third = Region::parse("cn").unwrap();
        store.submit(&first, &report(1.0)).unwrap();
        store.submit(&second, &report(1.0)).unwrap();
        assert_eq!(store.submit(&third, &report(1.0)), Err(Refusal::AtCapacity));
        store.submit(&first, &report(2.0)).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn a_region_nobody_reported_holds_nothing() {
        let store = MemoryReportStore::default();
        assert!(store.reports(&Region::parse("ru").unwrap()).is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn regions_come_back_in_one_stable_order() {
        let store = MemoryReportStore::default();
        for name in ["ru", "ir", "cn"] {
            store
                .submit(&Region::parse(name).unwrap(), &report(1.0))
                .unwrap();
        }
        let names: Vec<String> = store
            .regions()
            .iter()
            .map(|region| region.as_str().to_owned())
            .collect();
        assert_eq!(names, vec!["cn", "ir", "ru"]);
    }
}
