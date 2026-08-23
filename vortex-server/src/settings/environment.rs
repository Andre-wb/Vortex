use std::env;

pub fn text(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

pub fn text_or(name: &str, fallback: &str) -> String {
    text(name).unwrap_or_else(|| fallback.to_string())
}

pub fn number_or(name: &str, fallback: u16) -> u16 {
    text(name)
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

pub fn flag(name: &str, fallback: bool) -> bool {
    let Some(value) = text(name) else {
        return fallback;
    };
    matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

pub fn flag_strict(name: &str, fallback: bool) -> bool {
    match text(name) {
        Some(value) => value.eq_ignore_ascii_case("true"),
        None => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::{flag, flag_strict, number_or, text, text_or};

    #[test]
    fn a_blank_variable_reads_as_absent() {
        std::env::set_var("VORTEX_TEST_BLANK", "   ");
        assert_eq!(text("VORTEX_TEST_BLANK"), None);
        assert_eq!(text_or("VORTEX_TEST_BLANK", "по умолчанию"), "по умолчанию");
        std::env::remove_var("VORTEX_TEST_BLANK");
    }

    #[test]
    fn a_number_that_does_not_parse_falls_back() {
        std::env::set_var("VORTEX_TEST_PORT", "не число");
        assert_eq!(number_or("VORTEX_TEST_PORT", 9100), 9100);
        std::env::remove_var("VORTEX_TEST_PORT");
    }

    #[test]
    fn only_the_three_spellings_turn_a_flag_on() {
        for spelling in ["1", "true", "TRUE", "Yes"] {
            std::env::set_var("VORTEX_TEST_FLAG", spelling);
            assert!(flag("VORTEX_TEST_FLAG", false), "{spelling}");
        }
        std::env::set_var("VORTEX_TEST_FLAG", "on");
        assert!(!flag("VORTEX_TEST_FLAG", false));
        std::env::remove_var("VORTEX_TEST_FLAG");
    }

    #[test]
    fn the_strict_spelling_accepts_only_the_word_true() {
        std::env::set_var("VORTEX_TEST_STRICT", "1");
        assert!(!flag_strict("VORTEX_TEST_STRICT", true));
        std::env::set_var("VORTEX_TEST_STRICT", "True");
        assert!(flag_strict("VORTEX_TEST_STRICT", false));
        std::env::remove_var("VORTEX_TEST_STRICT");
        assert!(flag_strict("VORTEX_TEST_STRICT", true));
    }
}
