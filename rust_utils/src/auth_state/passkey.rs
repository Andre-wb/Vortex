use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vortex_auth::passkey::claim::Claim;

#[pyclass(name = "PasskeyClaim", module = "vortex_chat")]
pub struct PyPasskeyClaim {
    inner: Claim,
}

impl PyPasskeyClaim {
    pub fn of(inner: Claim) -> Self {
        PyPasskeyClaim { inner }
    }
}

#[pymethods]
impl PyPasskeyClaim {
    #[getter]
    fn outcome(&self) -> &'static str {
        self.inner.outcome()
    }

    #[getter]
    fn taken(&self) -> bool {
        self.inner.secret().is_some()
    }

    #[getter]
    fn challenge<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .secret()
            .map(|secret| PyBytes::new(py, secret.as_bytes()))
    }
}
