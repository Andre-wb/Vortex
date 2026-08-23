use crate::settings::environment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StealthSettings {
    enabled: bool,
}

impl StealthSettings {
    pub fn new(enabled: bool) -> Self {
        StealthSettings { enabled }
    }

    pub fn from_environment() -> Self {
        let testing = environment::text_or("TESTING", "").eq_ignore_ascii_case("true");
        StealthSettings::new(environment::flag("STEALTH_MODE", false) && !testing)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::StealthSettings;

    #[test]
    fn a_test_run_turns_stealth_off_even_when_the_variable_asks_for_it() {
        std::env::set_var("STEALTH_MODE", "true");
        std::env::set_var("TESTING", "true");
        assert!(!StealthSettings::from_environment().enabled());
        std::env::set_var("TESTING", "");
        assert!(StealthSettings::from_environment().enabled());
        std::env::remove_var("STEALTH_MODE");
        std::env::remove_var("TESTING");
    }
}
