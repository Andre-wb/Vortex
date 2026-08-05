//! Прогон текста через набор правил.
//!
//! Единственная точка, где правила применяются к данным. Инспекторы параметров,
//! тела и пути пользуются ею, а не таскают правила по отдельности.

use crate::domain::finding::Finding;
use crate::ports::clock::Clock;
use crate::ports::rule::Rule;
use crate::ports::rule_activity::RuleActivityRecorder;
use crate::scanning::safe_params::SafeParams;
use crate::util::truncate::take_chars;
use std::sync::Arc;

/// Сколько символов значения попадает в находку.
pub const VALUE_PREVIEW_CHARS: usize = 100;

pub struct FieldScanner {
    rules: Vec<Arc<dyn Rule>>,
    safe_params: SafeParams,
    activity: Arc<dyn RuleActivityRecorder>,
    clock: Arc<dyn Clock>,
}

impl FieldScanner {
    pub fn new(
        rules: Vec<Arc<dyn Rule>>,
        safe_params: SafeParams,
        activity: Arc<dyn RuleActivityRecorder>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        FieldScanner {
            rules,
            safe_params,
            activity,
            clock,
        }
    }

    pub fn rules(&self) -> &[Arc<dyn Rule>] {
        &self.rules
    }

    pub fn is_safe_param(&self, name: &str) -> bool {
        self.safe_params.contains(name)
    }

    /// Проверка именованного параметра: правило срабатывает и по имени, и по
    /// значению.
    pub fn scan_parameter(&self, name: &str, value: &str) -> Vec<Finding> {
        if self.safe_params.contains(name) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for rule in &self.rules {
            if rule.is_match(name) || rule.is_match(value) {
                let meta = rule.meta();
                findings.push(
                    Finding::new(meta.id.clone(), meta.severity)
                        .with_description(format!("{} in parameter {}", meta.description, name))
                        .with_value(take_chars(value, VALUE_PREVIEW_CHARS)),
                );
                self.activity.record_match(&meta.id, self.clock.now());
            }
        }
        findings
    }

    /// Сплошной прогон текста (тело целиком, путь). `context` попадает в
    /// описание: «… in request body», «… in URL path».
    pub fn scan_text(&self, text: &str, context: &str, include_value: bool) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            if rule.is_match(text) {
                let meta = rule.meta();
                let mut finding = Finding::new(meta.id.clone(), meta.severity)
                    .with_description(format!("{} in {}", meta.description, context));
                if include_value {
                    finding = finding.with_value(take_chars(text, VALUE_PREVIEW_CHARS));
                }
                findings.push(finding);
                self.activity.record_match(&meta.id, self.clock.now());
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::FieldScanner;
    use crate::domain::rule_id::RuleId;
    use crate::ports::rule_source::RuleSource;
    use crate::ports::stats_reporter::StatsReporter;
    use crate::rules::catalog_source::CatalogRuleSource;
    use crate::scanning::safe_params::SafeParams;
    use crate::stats::in_memory::InMemoryStats;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    fn scanner(safe: SafeParams) -> (FieldScanner, Arc<InMemoryStats>) {
        let stats = Arc::new(InMemoryStats::new());
        let rules = CatalogRuleSource::new().rules().unwrap();
        let scanner = FieldScanner::new(
            rules,
            safe,
            stats.clone(),
            Arc::new(ManualClock::at_epoch()),
        );
        (scanner, stats)
    }

    #[test]
    fn safe_params_are_skipped_entirely() {
        let (scanner, _) = scanner(SafeParams::default());
        assert!(scanner
            .scan_parameter("csrf_token", "' OR 1=1 --")
            .is_empty());
        assert!(!scanner.scan_parameter("comment", "' OR 1=1 --").is_empty());
    }

    #[test]
    fn rule_matches_on_the_parameter_name_too() {
        let (scanner, _) = scanner(SafeParams::empty());
        // Имя поля само по себе несёт обработчик события.
        let findings = scanner.scan_parameter("onerror=", "безобидное значение");
        assert!(findings
            .iter()
            .any(|f| f.rule_id.as_str().starts_with("XSS")));
    }

    #[test]
    fn value_preview_is_capped() {
        let (scanner, _) = scanner(SafeParams::empty());
        let payload = format!("javascript:{}", "a".repeat(500));
        let findings = scanner.scan_parameter("q", &payload);
        let preview = findings[0].value.as_deref().unwrap();
        assert_eq!(preview.chars().count(), 100);
    }

    #[test]
    fn matches_are_recorded_as_activity() {
        let (scanner, stats) = scanner(SafeParams::empty());
        scanner.scan_parameter("q", "javascript:alert(1)");
        assert!(stats.active_rule_count() > 0);
        assert!(stats.activity(&RuleId::from("XSS-012")).trigger_count > 0);
    }

    #[test]
    fn text_scan_can_omit_the_value() {
        let (scanner, _) = scanner(SafeParams::empty());
        let findings = scanner.scan_text("/etc/passwd", "URL path", false);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.value.is_none()));
        assert!(findings.iter().all(|f| f
            .description
            .as_deref()
            .unwrap()
            .ends_with("in URL path")));
    }
}
