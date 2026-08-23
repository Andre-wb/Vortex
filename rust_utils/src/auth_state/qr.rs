use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vortex_auth::qr::answer::Answer;
use vortex_auth::qr::handover::Handover;
use vortex_auth::qr::opened::OpenedSession;

#[pyclass(name = "QrSession", module = "vortex_chat")]
pub struct PyQrSession {
    inner: OpenedSession,
}

impl PyQrSession {
    pub fn of(inner: OpenedSession) -> Self {
        PyQrSession { inner }
    }
}

#[pymethods]
impl PyQrSession {
    #[getter]
    fn session_id(&self) -> &str {
        self.inner.session().as_str()
    }

    #[getter]
    fn challenge_id(&self) -> &str {
        self.inner.challenge().as_str()
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

#[pyclass(name = "QrAnswer", module = "vortex_chat")]
pub struct PyQrAnswer {
    inner: Answer,
}

impl PyQrAnswer {
    pub fn of(inner: Answer) -> Self {
        PyQrAnswer { inner }
    }
}

#[pymethods]
impl PyQrAnswer {
    #[getter]
    fn outcome(&self) -> &'static str {
        self.inner.outcome()
    }

    #[getter]
    fn ready(&self) -> bool {
        self.inner.secret().is_some()
    }

    #[getter]
    fn challenge<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .secret()
            .map(|secret| PyBytes::new(py, secret.as_bytes()))
    }
}

#[pyclass(name = "QrHandover", module = "vortex_chat")]
pub struct PyQrHandover {
    inner: Handover,
}

impl PyQrHandover {
    pub fn of(inner: Handover) -> Self {
        PyQrHandover { inner }
    }
}

#[pymethods]
impl PyQrHandover {
    #[getter]
    fn outcome(&self) -> &'static str {
        self.inner.outcome()
    }

    #[getter]
    fn taken(&self) -> bool {
        self.inner.user().is_some()
    }

    #[getter]
    fn user_id(&self) -> Option<i64> {
        self.inner.user().map(|user| user.value())
    }
}
