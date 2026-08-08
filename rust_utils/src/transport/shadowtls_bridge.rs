use parking_lot::Mutex;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::sync::Arc;
use vortex_transport::ports::random_source::RandomSource;
use vortex_transport::random::os_random::OsRandom;
use vortex_transport::shadowtls::donor::target::DonorTarget;
use vortex_transport::shadowtls::guard::ShadowTls;
use vortex_transport::shadowtls::relay::connection::Connection;
use vortex_transport::shadowtls::session::role::Role;
use vortex_transport::shadowtls::session::stream::SealedStream;
use vortex_transport::shadowtls::switch::sealer::SWITCH_PREFIX_LEN;
use vortex_transport::shadowtls::switch::session_id::{SessionId, SESSION_ID_LEN};
use vortex_transport::shadowtls::switch::token::SWITCH_TOKEN_LEN;
use vortex_transport::tls::record::scanner::{RecordScanner, ScanStep};
use vortex_transport::tls::server_hello::{self, ServerRandom, SERVER_RANDOM_LEN};
use vortex_transport::tls::server_name;

#[pyclass(module = "vortex_chat", name = "ShadowTls")]
pub struct PyShadowTls {
    guard: Mutex<Arc<ShadowTls>>,
    donors: Vec<DonorTarget>,
    random: Arc<dyn RandomSource>,
}

#[pymethods]
impl PyShadowTls {
    #[new]
    #[pyo3(signature = (password, previous_password="", donors=None))]
    fn new(password: &str, previous_password: &str, donors: Option<Vec<(String, u16)>>) -> Self {
        let donors: Vec<DonorTarget> = donors
            .unwrap_or_default()
            .into_iter()
            .map(|(host, port)| DonorTarget::new(host, port))
            .collect();
        PyShadowTls {
            guard: Mutex::new(Arc::new(build(password, previous_password, &donors))),
            donors,
            random: Arc::new(OsRandom::new()),
        }
    }

    #[pyo3(signature = (password, previous_password=""))]
    fn reload(&self, password: &str, previous_password: &str) {
        *self.guard.lock() = Arc::new(build(password, previous_password, &self.donors));
    }

    fn connection(&self) -> PyShadowTlsConnection {
        PyShadowTlsConnection {
            inner: Mutex::new(self.guard.lock().connection()),
        }
    }

    fn generate_session_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, SessionId::generate(self.random.as_ref()).as_bytes())
    }

    fn seal_switch<'py>(
        &self,
        py: Python<'py>,
        server_random: &[u8],
        session_id: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let record = self
            .guard
            .lock()
            .seal_switch(
                &to_server_random(server_random)?,
                &to_session_id(session_id)?,
                self.random.as_ref(),
            )
            .ok_or_else(unconfigured)?;
        Ok(PyBytes::new(py, &record))
    }

    fn seal_switch_derand<'py>(
        &self,
        py: Python<'py>,
        server_random: &[u8],
        session_id: &[u8],
        padding: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let guard = self.guard.lock();
        if !guard.is_configured() {
            return Err(unconfigured());
        }
        let record = guard
            .seal_switch_with_padding(
                &to_server_random(server_random)?,
                &to_session_id(session_id)?,
                padding,
            )
            .ok_or_else(|| {
                PyValueError::new_err(format!(
                    "switch-запись длиннее TLS-предела: {} байт паддинга",
                    padding.len()
                ))
            })?;
        Ok(PyBytes::new(py, &record))
    }

    #[staticmethod]
    fn parse_server_random<'py>(py: Python<'py>, data: &[u8]) -> Option<Bound<'py, PyBytes>> {
        server_hello::random(data).map(|random| PyBytes::new(py, &random))
    }

    #[staticmethod]
    fn parse_server_name(data: &[u8]) -> Option<String> {
        server_name::from_client_hello(data).map(str::to_string)
    }

    #[staticmethod]
    fn split_records(data: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>, bool) {
        let mut scanner = RecordScanner::new();
        scanner.push(data);
        let mut records = Vec::new();
        loop {
            match scanner.next_record() {
                ScanStep::Record(record) => records.push(record.into_bytes()),
                ScanStep::NeedMore => return (records, scanner.drain(), false),
                ScanStep::NotTls => return (records, scanner.drain(), true),
            }
        }
    }

    #[pyo3(signature = (server_random, session_id, server))]
    fn stream(
        &self,
        server_random: &[u8],
        session_id: &[u8],
        server: bool,
    ) -> PyResult<PyShadowTlsStream> {
        let stream = self
            .guard
            .lock()
            .stream(
                &to_server_random(server_random)?,
                &to_session_id(session_id)?,
                role(server),
            )
            .ok_or_else(unconfigured)?;
        Ok(PyShadowTlsStream {
            inner: Mutex::new(stream),
        })
    }

    #[getter]
    fn is_configured(&self) -> bool {
        self.guard.lock().is_configured()
    }

    #[getter]
    fn accepts_previous(&self) -> bool {
        self.guard.lock().accepts_previous()
    }

    #[getter]
    fn donors(&self) -> Vec<(String, u16)> {
        self.guard
            .lock()
            .donors()
            .targets()
            .iter()
            .map(|target| (target.host.clone(), target.port))
            .collect()
    }

    fn status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let guard = self.guard.lock();
        let status = PyDict::new(py);
        status.set_item("protocol", "shadowtls_v3")?;
        status.set_item("switch_binding", "donor_server_random")?;
        status.set_item("handshake_targets", guard.donors().targets().len())?;
        status.set_item("marker_len", SWITCH_TOKEN_LEN)?;
        status.set_item("configured", guard.is_configured())?;
        status.set_item("accepts_previous", guard.accepts_previous())?;
        Ok(status)
    }

    #[getter]
    fn session_id_len(&self) -> usize {
        SESSION_ID_LEN
    }

    #[getter]
    fn switch_prefix_len(&self) -> usize {
        SWITCH_PREFIX_LEN
    }

    #[getter]
    fn server_random_len(&self) -> usize {
        SERVER_RANDOM_LEN
    }
}

#[pyclass(module = "vortex_chat", name = "ShadowTlsConnection")]
pub struct PyShadowTlsConnection {
    inner: Mutex<Connection>,
}

#[pymethods]
impl PyShadowTlsConnection {
    fn feed_client(&self, py: Python<'_>, chunk: &[u8]) -> PyShadowTlsClientStep {
        let step = py.allow_threads(|| self.inner.lock().feed_client(chunk));
        PyShadowTlsClientStep {
            forward: step.forward,
            switch: step.switch.map(|value| *value.as_bytes()),
            trailing: step.trailing,
            opaque: step.opaque,
        }
    }

    fn feed_donor(&self, py: Python<'_>, chunk: &[u8]) -> PyShadowTlsDonorStep {
        let step = py.allow_threads(|| self.inner.lock().feed_donor(chunk));
        PyShadowTlsDonorStep {
            forward: step.forward,
            opaque: step.opaque,
        }
    }

    fn donor(&self) -> Option<(String, u16)> {
        self.inner
            .lock()
            .donor()
            .map(|target| (target.host.clone(), target.port))
    }

    #[getter]
    fn server_random<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .lock()
            .server_random()
            .map(|random| PyBytes::new(py, random))
    }

    #[getter]
    fn session_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .lock()
            .session_id()
            .map(|value| PyBytes::new(py, value.as_bytes()))
    }

    #[getter]
    fn has_switched(&self) -> bool {
        self.inner.lock().has_switched()
    }

    #[pyo3(signature = (server=true))]
    fn stream(&self, server: bool) -> Option<PyShadowTlsStream> {
        self.inner
            .lock()
            .stream(role(server))
            .map(|stream| PyShadowTlsStream {
                inner: Mutex::new(stream),
            })
    }
}

#[pyclass(module = "vortex_chat", name = "ShadowTlsClientStep")]
pub struct PyShadowTlsClientStep {
    forward: Vec<u8>,
    switch: Option<[u8; SESSION_ID_LEN]>,
    trailing: Vec<u8>,
    opaque: bool,
}

#[pymethods]
impl PyShadowTlsClientStep {
    #[getter]
    fn forward<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.forward)
    }

    #[getter]
    fn session_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.switch.map(|value| PyBytes::new(py, &value))
    }

    #[getter]
    fn trailing<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.trailing)
    }

    #[getter]
    fn opaque(&self) -> bool {
        self.opaque
    }
}

#[pyclass(module = "vortex_chat", name = "ShadowTlsDonorStep")]
pub struct PyShadowTlsDonorStep {
    forward: Vec<u8>,
    opaque: bool,
}

#[pymethods]
impl PyShadowTlsDonorStep {
    #[getter]
    fn forward<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.forward)
    }

    #[getter]
    fn opaque(&self) -> bool {
        self.opaque
    }
}

#[pyclass(module = "vortex_chat", name = "ShadowTlsStream")]
pub struct PyShadowTlsStream {
    inner: Mutex<SealedStream>,
}

#[pymethods]
impl PyShadowTlsStream {
    fn wrap<'py>(&self, py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
        let sealed = py.allow_threads(|| self.inner.lock().wrap(data));
        PyBytes::new(py, &sealed)
    }

    fn unwrap<'py>(&self, py: Python<'py>, frame: &[u8]) -> Option<Bound<'py, PyBytes>> {
        let opened = py.allow_threads(|| self.inner.lock().unwrap(frame));
        opened.map(|data| PyBytes::new(py, &data))
    }
}

fn build(password: &str, previous_password: &str, donors: &[DonorTarget]) -> ShadowTls {
    let guard = ShadowTls::new(password.as_bytes(), previous_password.as_bytes());
    if donors.is_empty() {
        return guard;
    }
    guard.with_donors(donors.to_vec())
}

fn role(server: bool) -> Role {
    if server {
        Role::Server
    } else {
        Role::Client
    }
}

fn unconfigured() -> PyErr {
    PyValueError::new_err("пароль ShadowTLS не задан: переключение и поток недоступны")
}

fn to_server_random(bytes: &[u8]) -> PyResult<ServerRandom> {
    bytes.try_into().map_err(|_| {
        PyValueError::new_err(format!(
            "random сервера должен быть длиной {SERVER_RANDOM_LEN} байт, получено {}",
            bytes.len()
        ))
    })
}

fn to_session_id(bytes: &[u8]) -> PyResult<SessionId> {
    SessionId::parse(bytes).ok_or_else(|| {
        PyValueError::new_err(format!(
            "session_id должен быть длиной {SESSION_ID_LEN} байт, получено {}",
            bytes.len()
        ))
    })
}
