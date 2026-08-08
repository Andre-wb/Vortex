use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Arc;
use vortex_redis::transport::report_store::RedisReportStore;
use vortex_transport::censorship::config::DashboardConfig;
use vortex_transport::censorship::dashboard::{CensorshipDashboard, RegionStatus};
use vortex_transport::censorship::refusal::Refusal;

#[pyclass(module = "vortex_chat", name = "CensorshipRejection", frozen)]
#[derive(Clone)]
pub struct PyCensorshipRejection {
    #[pyo3(get)]
    pub status: u16,
    #[pyo3(get)]
    pub detail: String,
    #[pyo3(get)]
    pub reason: String,
}

impl PyCensorshipRejection {
    fn of(refusal: Refusal) -> Self {
        PyCensorshipRejection {
            status: refusal.status(),
            detail: refusal.to_string(),
            reason: refusal.as_str().to_owned(),
        }
    }
}

#[pymethods]
impl PyCensorshipRejection {
    fn __repr__(&self) -> String {
        format!(
            "<CensorshipRejection status={} reason={}>",
            self.status, self.reason
        )
    }
}

#[pyclass(module = "vortex_chat", name = "CensorshipDashboard")]
pub struct PyCensorshipDashboard {
    dashboard: CensorshipDashboard,
    shared: bool,
}

#[pymethods]
impl PyCensorshipDashboard {
    #[new]
    #[pyo3(signature = (max_regions=None, max_reports_per_region=None))]
    fn new(max_regions: Option<usize>, max_reports_per_region: Option<usize>) -> Self {
        let mut config = DashboardConfig::default();
        if let Some(regions) = max_regions {
            config = config.max_regions(regions);
        }
        if let Some(reports) = max_reports_per_region {
            config = config.max_reports_per_region(reports);
        }

        match crate::bmp::shared::backbone() {
            Some(backbone) => PyCensorshipDashboard {
                dashboard: CensorshipDashboard::with_store(
                    config,
                    Arc::new(RedisReportStore::with_config(backbone, config)),
                ),
                shared: true,
            },
            None => PyCensorshipDashboard {
                dashboard: CensorshipDashboard::new(config),
                shared: false,
            },
        }
    }

    fn submit(
        &self,
        py: Python<'_>,
        region: &str,
        transports: Vec<(String, bool)>,
        now: f64,
    ) -> (Option<String>, Option<PyCensorshipRejection>) {
        match py.allow_threads(|| self.dashboard.submit(region, &transports, now)) {
            Ok(recommended) => (Some(recommended.to_owned()), None),
            Err(refusal) => (None, Some(PyCensorshipRejection::of(refusal))),
        }
    }

    fn recommended(&self, region: &str) -> String {
        self.dashboard.recommended(region).to_owned()
    }

    fn blocked(&self, region: &str) -> Vec<String> {
        self.dashboard
            .blocked(region)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn region_status<'py>(
        &self,
        py: Python<'py>,
        region: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        match self.dashboard.status(region) {
            Some(status) => Ok(Some(described(py, &status)?)),
            None => Ok(None),
        }
    }

    fn all_regions<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let out = PyDict::new(py);
        for status in self.dashboard.all_regions() {
            out.set_item(status.region.clone(), described(py, &status)?)?;
        }
        Ok(out)
    }

    fn status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let regions = self.all_regions(py)?;
        let out = PyDict::new(py);
        out.set_item("regions_monitored", regions.len())?;
        out.set_item("shared_state", self.shared)?;
        out.set_item("regions", regions)?;
        Ok(out)
    }

    #[getter]
    fn is_shared(&self) -> bool {
        self.shared
    }

    #[getter]
    fn regions(&self) -> usize {
        self.dashboard.regions()
    }

    #[getter]
    fn max_regions(&self) -> usize {
        self.dashboard.config().max_regions
    }

    #[getter]
    fn reports_for_verdict(&self) -> usize {
        self.dashboard.config().reports_for_verdict
    }
}

fn described<'py>(py: Python<'py>, status: &RegionStatus) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("region", status.region.clone())?;
    out.set_item("total_reports", status.total_reports)?;
    out.set_item("blocked_transports", status.blocked.clone())?;
    out.set_item("recommended_transport", status.recommended)?;
    match &status.last_report {
        Some(report) => {
            let last = PyDict::new(py);
            last.set_item("received_at", report.received_at)?;
            let transports = PyDict::new(py);
            for verdict in &report.verdicts {
                transports.set_item(verdict.transport, verdict.ok)?;
            }
            last.set_item("transports", transports)?;
            out.set_item("last_report", last)?;
        }
        None => out.set_item("last_report", py.None())?,
    }
    Ok(out)
}
