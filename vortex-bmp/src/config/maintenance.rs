pub const DEFAULT_GC_INTERVAL_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceConfig {
    pub interval_secs: u64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        MaintenanceConfig {
            interval_secs: DEFAULT_GC_INTERVAL_SECS,
        }
    }
}

impl MaintenanceConfig {
    pub fn new() -> Self {
        MaintenanceConfig::default()
    }

    pub fn interval_secs(mut self, seconds: u64) -> Self {
        self.interval_secs = seconds;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::MaintenanceConfig;

    #[test]
    fn the_default_interval_matches_the_python_loop() {
        assert_eq!(MaintenanceConfig::default().interval_secs, 300);
    }
}
