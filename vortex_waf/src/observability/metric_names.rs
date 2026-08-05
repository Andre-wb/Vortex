pub const REQUESTS_TOTAL: &str = "vortex_waf_requests_total";

pub const BLOCKED_REQUESTS_TOTAL: &str = "vortex_waf_blocked_requests_total";

pub const IP_BLOCKS_TOTAL: &str = "vortex_waf_ip_blocks_total";

pub const RULE_TRIGGERS_TOTAL: &str = "vortex_waf_rule_triggers_total";

pub const RULE_LABEL: &str = "rule";

pub const BLOCKED_IPS: &str = "vortex_waf_blocked_ips";

pub const RULES_LOADED: &str = "vortex_waf_rules_loaded";

pub const COUNTERS: &[(&str, &str)] = &[
    (REQUESTS_TOTAL, "total_requests"),
    (BLOCKED_REQUESTS_TOTAL, "blocked_requests"),
    (IP_BLOCKS_TOTAL, "ip_blocks"),
];

pub const GAUGES: &[(&str, &str)] = &[
    (BLOCKED_IPS, "blocked_ips_count"),
    (RULES_LOADED, "rules_loaded"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn all_names() -> Vec<&'static str> {
        COUNTERS
            .iter()
            .chain(GAUGES.iter())
            .map(|(name, _)| *name)
            .chain(std::iter::once(RULE_TRIGGERS_TOTAL))
            .collect()
    }

    #[test]
    fn names_are_unique() {
        let names = all_names();
        let unique: BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
    }

    #[test]
    fn every_name_is_namespaced() {
        for name in all_names() {
            assert!(name.starts_with("vortex_waf_"), "{name}");
        }
    }

    #[test]
    fn counters_end_with_total_and_gauges_do_not() {
        for (name, _) in COUNTERS {
            assert!(name.ends_with("_total"), "{name}");
        }
        assert!(RULE_TRIGGERS_TOTAL.ends_with("_total"));
        for (name, _) in GAUGES {
            assert!(!name.ends_with("_total"), "{name}");
        }
    }
}
