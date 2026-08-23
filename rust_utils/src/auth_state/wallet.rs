use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vortex_auth::wallet::issued::IssuedChallenge;
use vortex_auth::wallet::verification::Verification;

#[pyclass(name = "WalletChallenge", module = "vortex_chat")]
pub struct PyWalletChallenge {
    inner: IssuedChallenge,
}

impl PyWalletChallenge {
    pub fn of(inner: IssuedChallenge) -> Self {
        PyWalletChallenge { inner }
    }
}

#[pymethods]
impl PyWalletChallenge {
    #[getter]
    fn challenge(&self) -> String {
        self.inner.rendered()
    }

    #[getter]
    fn expires_at(&self) -> i64 {
        self.inner.expires_at()
    }

    #[getter]
    fn ttl_seconds(&self) -> u64 {
        self.inner.ttl_seconds()
    }
}

#[pyclass(name = "WalletChallengeCheck", module = "vortex_chat")]
pub struct PyWalletCheck {
    inner: Verification,
}

impl PyWalletCheck {
    pub fn of(inner: Verification) -> Self {
        PyWalletCheck { inner }
    }
}

#[pymethods]
impl PyWalletCheck {
    #[getter]
    fn outcome(&self) -> &'static str {
        self.inner.outcome()
    }

    #[getter]
    fn matched(&self) -> bool {
        self.inner.matched().is_some()
    }

    #[getter]
    fn message<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .matched()
            .map(|message| PyBytes::new(py, message.as_bytes()))
    }
}
