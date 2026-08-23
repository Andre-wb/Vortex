use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vortex_auth::login::claim::AccountClaim;
use vortex_auth::login::issued::IssuedChallenge;

#[pyclass(name = "LoginChallenge", module = "vortex_chat")]
pub struct PyLoginChallenge {
    inner: IssuedChallenge,
}

impl PyLoginChallenge {
    pub fn of(inner: IssuedChallenge) -> Self {
        PyLoginChallenge { inner }
    }
}

#[pymethods]
impl PyLoginChallenge {
    #[getter]
    fn challenge_id(&self) -> &str {
        self.inner.id().as_str()
    }

    #[getter]
    fn challenge<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.secret().as_bytes())
    }

    #[getter]
    fn expires_in(&self) -> u64 {
        self.inner.expires_in()
    }
}

#[pyclass(name = "LoginClaim", module = "vortex_chat")]
pub struct PyLoginClaim {
    inner: AccountClaim,
}

impl PyLoginClaim {
    pub fn of(inner: AccountClaim) -> Self {
        PyLoginClaim { inner }
    }
}

#[pymethods]
impl PyLoginClaim {
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

    #[getter]
    fn user_id(&self) -> Option<i64> {
        self.inner.user().map(|user| user.value())
    }
}
