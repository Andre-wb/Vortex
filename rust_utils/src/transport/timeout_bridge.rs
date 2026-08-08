use pyo3::prelude::*;
use vortex_transport::timeout::budget::ReadBudget;
use vortex_transport::timeout::config::TimeoutConfig;

#[pyclass(module = "vortex_chat", name = "ReadDeadline")]
pub struct PyReadDeadline {
    budget: ReadBudget,
}

#[pymethods]
impl PyReadDeadline {
    #[new]
    #[pyo3(signature = (now, seconds=None))]
    fn new(now: f64, seconds: Option<f64>) -> Self {
        let config = TimeoutConfig::default();
        PyReadDeadline {
            budget: match seconds {
                Some(seconds) => ReadBudget::start(now, seconds),
                None => ReadBudget::handshake(now, &config),
            },
        }
    }

    fn remaining(&self, now: f64) -> f64 {
        self.budget.remaining(now)
    }

    fn expired(&self, now: f64) -> bool {
        self.budget.expired(now)
    }

    #[getter]
    fn seconds(&self) -> f64 {
        self.budget.seconds()
    }
}

pub fn handshake_timeout_secs() -> f64 {
    TimeoutConfig::default().handshake_secs
}
