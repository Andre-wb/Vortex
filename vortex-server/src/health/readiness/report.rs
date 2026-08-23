use serde::Serialize;
use serde_json::Value;

use crate::health::facts::ReadinessFacts;
use crate::health::readiness::checks::LocalChecks;

pub const READY: &str = "ready";
pub const DEGRADED: &str = "degraded";
pub const READY_CODE: u16 = 200;
pub const DEGRADED_CODE: u16 = 503;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReadinessReport {
    pub status: &'static str,
    pub database: Value,
    pub uploads_dir: String,
    pub keys_dir: String,
    pub background_tasks: Value,
}

impl ReadinessReport {
    pub fn compose(checks: LocalChecks, facts: ReadinessFacts) -> Self {
        let ready = checks.passed() && facts.status == READY_CODE;
        ReadinessReport {
            status: if ready { READY } else { DEGRADED },
            database: facts.database,
            uploads_dir: checks.uploads_dir,
            keys_dir: checks.keys_dir,
            background_tasks: facts.background_tasks,
        }
    }

    pub fn code(&self) -> u16 {
        if self.status == READY {
            READY_CODE
        } else {
            DEGRADED_CODE
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ReadinessReport, DEGRADED, DEGRADED_CODE, READY, READY_CODE};
    use crate::health::facts::ReadinessFacts;
    use crate::health::readiness::checks::LocalChecks;

    fn passing() -> LocalChecks {
        LocalChecks {
            uploads_dir: "ok".to_string(),
            keys_dir: "ok".to_string(),
        }
    }

    #[test]
    fn both_halves_must_pass_for_the_node_to_be_ready() {
        let report = ReadinessReport::compose(
            passing(),
            ReadinessFacts::read(
                READY_CODE,
                &json!({"database": "ok", "background_tasks": "2/2 alive"}),
            ),
        );
        assert_eq!(report.status, READY);
        assert_eq!(report.code(), READY_CODE);
    }

    #[test]
    fn a_degraded_python_half_degrades_the_whole_answer() {
        let report = ReadinessReport::compose(
            passing(),
            ReadinessFacts::read(DEGRADED_CODE, &json!({"database": "error: нет базы"})),
        );
        assert_eq!(report.status, DEGRADED);
        assert_eq!(report.code(), DEGRADED_CODE);
    }

    #[test]
    fn a_failed_local_check_degrades_the_answer_even_when_python_is_ready() {
        let checks = LocalChecks {
            uploads_dir: "error: нет каталога".to_string(),
            keys_dir: "ok".to_string(),
        };
        let report = ReadinessReport::compose(
            checks,
            ReadinessFacts::read(READY_CODE, &json!({"database": "ok"})),
        );
        assert_eq!(report.status, DEGRADED);
    }

    #[test]
    fn the_key_order_matches_the_python_answer() {
        let report = ReadinessReport::compose(
            passing(),
            ReadinessFacts::read(
                READY_CODE,
                &json!({"database": "ok", "background_tasks": "1/1 alive"}),
            ),
        );
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(rendered.starts_with(r#"{"status":"ready","database":"ok","uploads_dir":"ok","keys_dir":"ok","background_tasks":"1/1 alive"}"#));
    }
}
