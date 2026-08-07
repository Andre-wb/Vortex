use crate::config::rate::RateConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateClass {
    Standard,
    Fast,
}

impl RateClass {
    pub fn limit(&self, config: &RateConfig) -> u32 {
        match self {
            RateClass::Standard => config.standard_per_window,
            RateClass::Fast => config.fast_per_window,
        }
    }

    pub fn prefix(&self) -> &'static str {
        match self {
            RateClass::Standard => "std",
            RateClass::Fast => "fast",
        }
    }

    pub fn window_key(&self, client: &str) -> String {
        format!("{}:{}", self.prefix(), client)
    }
}

#[cfg(test)]
mod tests {
    use super::RateClass;
    use crate::config::rate::RateConfig;

    #[test]
    fn fast_polling_is_allowed_far_more_requests() {
        let config = RateConfig::default();
        assert_eq!(RateClass::Standard.limit(&config), 600);
        assert_eq!(RateClass::Fast.limit(&config), 3000);
    }

    #[test]
    fn each_class_counts_in_its_own_window() {
        assert_ne!(
            RateClass::Standard.window_key("1.2.3.4"),
            RateClass::Fast.window_key("1.2.3.4")
        );
    }
}
