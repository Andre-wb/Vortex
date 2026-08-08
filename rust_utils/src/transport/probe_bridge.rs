use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::sync::Arc;
use vortex_transport::probe::config::ProbeConfig;
use vortex_transport::probe::guard::CensorshipProbe;
use vortex_transport::probe::outcome::Outcome;
use vortex_transport::random::os_random::OsRandom;

#[pyclass(module = "vortex_chat", name = "ProbeTarget")]
pub struct PyProbeTarget {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    timeout: f64,
    #[pyo3(get)]
    accepted: Vec<u16>,
    #[pyo3(get)]
    accept_header: Option<String>,
}

#[pymethods]
impl PyProbeTarget {
    fn __repr__(&self) -> String {
        format!("ProbeTarget({}, {})", self.name, self.path)
    }
}

#[pyclass(module = "vortex_chat", name = "CensorshipProbe")]
pub struct PyCensorshipProbe {
    probe: CensorshipProbe,
}

#[pymethods]
impl PyCensorshipProbe {
    #[new]
    #[pyo3(signature = (base_interval=None, run_timeout=None))]
    fn new(base_interval: Option<f64>, run_timeout: Option<f64>) -> Self {
        let mut config = ProbeConfig::default();
        if let Some(seconds) = base_interval {
            config = config.base_interval_secs(seconds);
        }
        if let Some(seconds) = run_timeout {
            config = config.run_timeout_secs(seconds);
        }
        PyCensorshipProbe {
            probe: CensorshipProbe::new(config, Arc::new(OsRandom::new())),
        }
    }

    fn plan(&self) -> Vec<PyProbeTarget> {
        self.probe
            .plan()
            .into_iter()
            .map(|target| PyProbeTarget {
                timeout: self.probe.timeout_of(target.name).unwrap_or_default(),
                name: target.name.to_owned(),
                path: target.path,
                accepted: target.accepted,
                accept_header: target.accept_header.map(str::to_owned),
            })
            .collect()
    }

    fn answered(&self, name: &str, status: u16, latency_ms: i64) -> bool {
        match self.probe.read(name, status, latency_ms) {
            Some(outcome) => {
                let ok = outcome.ok;
                self.probe.record(name, outcome) && ok
            }
            None => false,
        }
    }

    fn failed(&self, name: &str, error: &str, latency_ms: i64) -> bool {
        self.probe.record(name, Outcome::failed(error, latency_ms))
    }

    fn timed_out(&self, name: &str) -> bool {
        self.probe.record(name, Outcome::timed_out())
    }

    fn finish(&self, now: f64) -> Option<String> {
        self.probe.finish(now).map(str::to_owned)
    }

    fn due(&self, now: f64) -> bool {
        self.probe.due(now)
    }

    fn serves(&self, token: &str) -> Option<String> {
        self.probe.serves(token).map(str::to_owned)
    }

    fn token(&self, name: &str) -> Option<String> {
        vortex_transport::probe::catalogue::by_name(name).map(|probe| probe.token().to_hex())
    }

    fn results<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let out = PyDict::new(py);
        for (name, outcome) in self.probe.results().iter() {
            let entry = PyDict::new(py);
            entry.set_item("ok", outcome.ok)?;
            entry.set_item("latency", outcome.latency_ms)?;
            if let Some(status) = outcome.status {
                entry.set_item("status", status)?;
            }
            if let Some(error) = &outcome.error {
                entry.set_item("error", error)?;
            }
            out.set_item(name, entry)?;
        }
        Ok(out)
    }

    #[getter]
    fn best(&self) -> Option<String> {
        self.probe.best().map(str::to_owned)
    }

    #[getter]
    fn last_run(&self) -> f64 {
        self.probe.last_run().unwrap_or(0.0)
    }

    #[getter]
    fn interval(&self) -> f64 {
        self.probe.interval_secs()
    }

    #[getter]
    fn run_timeout(&self) -> f64 {
        self.probe.config().run_timeout_secs
    }

    #[getter]
    fn transports<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        PyList::new(py, vortex_transport::probe::catalogue::names())
            .expect("список транспортов всегда собирается")
    }
}
