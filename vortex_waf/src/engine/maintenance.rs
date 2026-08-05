//! Периодическая уборка состояния.

use crate::ports::prunable::Prunable;
use std::sync::Arc;

/// Отчёт об уборке: имя компонента и число удалённых записей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneReport {
    pub component: &'static str,
    pub removed: usize,
}

#[derive(Default)]
pub struct MaintenanceService {
    targets: Vec<Arc<dyn Prunable>>,
}

impl MaintenanceService {
    pub fn new(targets: Vec<Arc<dyn Prunable>>) -> Self {
        MaintenanceService { targets }
    }

    pub fn run(&self) -> Vec<PruneReport> {
        self.targets
            .iter()
            .map(|target| PruneReport {
                component: target.name(),
                removed: target.prune(),
            })
            .collect()
    }

    pub fn total_removed(&self) -> usize {
        self.run().iter().map(|r| r.removed).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::MaintenanceService;
    use crate::ports::prunable::Prunable;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    struct CountingTarget {
        calls: AtomicUsize,
    }

    impl Prunable for CountingTarget {
        fn name(&self) -> &'static str {
            "counter"
        }

        fn prune(&self) -> usize {
            self.calls.fetch_add(1, Ordering::Relaxed);
            2
        }
    }

    #[test]
    fn visits_every_target() {
        let target = Arc::new(CountingTarget::default());
        let service = MaintenanceService::new(vec![target.clone(), target.clone()]);
        let reports = service.run();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].removed, 2);
        assert_eq!(target.calls.load(Ordering::Relaxed), 2);
    }
}
