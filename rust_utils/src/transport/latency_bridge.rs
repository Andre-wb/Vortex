use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Arc;
use vortex_transport::latency::config::LatencyConfig;
use vortex_transport::latency::monitor::LatencyMonitor;
use vortex_transport::latency::stats::Stats;
use vortex_transport::latency::verdict::Verdict;
use vortex_transport::random::os_random::OsRandom;

#[pyclass(module = "vortex_chat", name = "LatencyMonitor")]
pub struct PyLatencyMonitor {
    monitor: LatencyMonitor,
}

#[pymethods]
impl PyLatencyMonitor {
    #[new]
    #[pyo3(signature = (probe_interval=None))]
    fn new(probe_interval: Option<f64>) -> Self {
        let mut config = LatencyConfig::default();
        if let Some(seconds) = probe_interval {
            config = config.probe_interval_secs(seconds);
        }
        PyLatencyMonitor {
            monitor: LatencyMonitor::new(config, Arc::new(OsRandom::new())),
        }
    }

    fn record(&self, transport: &str, latency_ms: f64, now: f64) -> &'static str {
        match self.monitor.record(transport, latency_ms, now) {
            Verdict::Fine => "fine",
            Verdict::Blocked => "blocked",
            Verdict::Degraded => "degraded",
        }
    }

    fn next_wait(&self) -> f64 {
        self.monitor.next_wait()
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let out = PyDict::new(py);
        for (transport, stats) in self.monitor.all_stats() {
            out.set_item(transport, measured(py, &stats)?)?;
        }
        Ok(out)
    }

    fn stats_of<'py>(&self, py: Python<'py>, transport: &str) -> PyResult<Bound<'py, PyDict>> {
        let stats = self.monitor.stats(transport).unwrap_or(Stats::of(&[]));
        measured(py, &stats)
    }

    #[pyo3(signature = (limit=20))]
    fn alerts<'py>(&self, py: Python<'py>, limit: usize) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let mut out = Vec::new();
        for alert in self.monitor.recent_alerts(limit) {
            let entry = PyDict::new(py);
            entry.set_item("transport", alert.transport)?;
            entry.set_item("type", alert.kind.as_str())?;
            entry.set_item("timestamp", alert.timestamp)?;
            if alert.latency_ms >= 0.0 {
                entry.set_item("latency", alert.latency_ms)?;
                entry.set_item("average", alert.average_ms)?;
            }
            out.push(entry);
        }
        Ok(out)
    }

    #[getter]
    fn tracked(&self) -> usize {
        self.monitor.tracked()
    }

    #[getter]
    fn probe_interval(&self) -> f64 {
        self.monitor.config().probe_interval_secs
    }
}

fn measured<'py>(py: Python<'py>, stats: &Stats) -> PyResult<Bound<'py, PyDict>> {
    let entry = PyDict::new(py);
    entry.set_item("current", stats.current)?;
    entry.set_item("avg", stats.average as i64)?;
    entry.set_item("min", stats.best as i64)?;
    entry.set_item("max", stats.worst as i64)?;
    entry.set_item("failures", stats.failures)?;
    entry.set_item("total_probes", stats.total)?;
    Ok(entry)
}
