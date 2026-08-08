pub const DEFAULT_MAX_REPORTS_PER_REGION: usize = 100;
pub const DEFAULT_MAX_REGIONS: usize = 512;
pub const DEFAULT_QUORUM_RATIO: f64 = 0.5;
pub const DEFAULT_REPORTS_FOR_VERDICT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DashboardConfig {
    pub max_reports_per_region: usize,
    pub max_regions: usize,
    pub quorum_ratio: f64,
    pub reports_for_verdict: usize,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        DashboardConfig {
            max_reports_per_region: DEFAULT_MAX_REPORTS_PER_REGION,
            max_regions: DEFAULT_MAX_REGIONS,
            quorum_ratio: DEFAULT_QUORUM_RATIO,
            reports_for_verdict: DEFAULT_REPORTS_FOR_VERDICT,
        }
    }
}

impl DashboardConfig {
    pub fn max_reports_per_region(mut self, reports: usize) -> Self {
        self.max_reports_per_region = reports;
        self
    }

    pub fn max_regions(mut self, regions: usize) -> Self {
        self.max_regions = regions;
        self
    }

    pub fn reports_for_verdict(mut self, reports: usize) -> Self {
        self.reports_for_verdict = reports;
        self
    }

    pub fn quorum_ratio(mut self, ratio: f64) -> Self {
        self.quorum_ratio = ratio;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::DashboardConfig;

    #[test]
    fn one_client_alone_never_decides_for_a_region() {
        assert!(DashboardConfig::default().reports_for_verdict > 1);
    }

    #[test]
    fn a_region_holds_more_reports_than_a_verdict_needs() {
        let config = DashboardConfig::default();
        assert!(config.max_reports_per_region > config.reports_for_verdict);
    }

    #[test]
    fn the_number_of_regions_is_bounded() {
        assert!(DashboardConfig::default().max_regions > 0);
    }
}
