use serde::Serialize;

use crate::prekey::limits::LOW_ONE_TIME_THRESHOLD;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReport {
    pub published: bool,
    pub signed_prekey_id: Option<i64>,
    pub available_opk_count: i64,
    pub low_opk_warning: bool,
    pub supports_v2: Option<bool>,
}

impl StatusReport {
    pub fn unpublished() -> Self {
        StatusReport {
            published: false,
            signed_prekey_id: None,
            available_opk_count: 0,
            low_opk_warning: true,
            supports_v2: None,
        }
    }

    pub fn published(signed_prekey_id: i64, available: i64, supports_v2: Option<bool>) -> Self {
        StatusReport {
            published: true,
            signed_prekey_id: Some(signed_prekey_id),
            available_opk_count: available,
            low_opk_warning: available < LOW_ONE_TIME_THRESHOLD,
            supports_v2,
        }
    }

    pub fn needs_replenishment(available: i64) -> bool {
        available < LOW_ONE_TIME_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::StatusReport;
    use crate::prekey::limits::LOW_ONE_TIME_THRESHOLD;

    #[test]
    fn a_device_that_never_published_is_told_to_replenish() {
        let report = StatusReport::unpublished();
        assert!(!report.published);
        assert!(report.low_opk_warning);
        assert_eq!(report.available_opk_count, 0);
        assert!(report.signed_prekey_id.is_none());
    }

    #[test]
    fn the_warning_turns_off_exactly_at_the_threshold() {
        assert!(StatusReport::published(0, LOW_ONE_TIME_THRESHOLD - 1, None).low_opk_warning);
        assert!(!StatusReport::published(0, LOW_ONE_TIME_THRESHOLD, None).low_opk_warning);
    }

    #[test]
    fn the_capability_flag_is_reported_as_stored() {
        assert_eq!(
            StatusReport::published(1, 20, Some(true)).supports_v2,
            Some(true)
        );
        assert_eq!(StatusReport::published(1, 20, None).supports_v2, None);
    }

    #[test]
    fn the_replenishment_rule_is_the_one_the_report_uses() {
        assert!(StatusReport::needs_replenishment(
            LOW_ONE_TIME_THRESHOLD - 1
        ));
        assert!(!StatusReport::needs_replenishment(LOW_ONE_TIME_THRESHOLD));
    }
}
