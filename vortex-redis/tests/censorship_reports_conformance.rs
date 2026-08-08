mod support;

use std::sync::Arc;

use vortex_redis::transport::report_store::RedisReportStore;
use vortex_transport::censorship::config::DashboardConfig;
use vortex_transport::ports::report_store::ReportStore;
use vortex_transport::testing::report_store_conformance;

#[test]
fn the_redis_report_store_satisfies_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("reports-probe")).is_none() {
        eprintln!("Redis недоступен — проверка панели блокировок пропущена");
        return;
    }
    let make = |config: DashboardConfig| -> Arc<dyn ReportStore> {
        let prefix = support::unique_prefix("reports");
        Arc::new(RedisReportStore::with_config(
            support::backbone(&prefix).unwrap(),
            config,
        ))
    };
    report_store_conformance::check_all(&make);
}
