use std::sync::Arc;

use vortex_transport::censorship::config::DashboardConfig;
use vortex_transport::censorship::store::memory_reports::MemoryReportStore;
use vortex_transport::ports::report_store::ReportStore;
use vortex_transport::testing::report_store_conformance;

#[test]
fn the_in_memory_report_store_satisfies_the_port_contract() {
    let make = |config: DashboardConfig| -> Arc<dyn ReportStore> {
        Arc::new(MemoryReportStore::new(config))
    };
    report_store_conformance::check_all(&make);
}
