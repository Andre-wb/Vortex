use parking_lot::Mutex;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::sync::Arc;
use vortex_transport::ports::random_source::RandomSource;
use vortex_transport::random::os_random::OsRandom;
use vortex_transport::shadowsocks::frame::limits::{MAX_FRAME, MAX_PAYLOAD};
use vortex_transport::shadowsocks::frame::step::FrameStep;
use vortex_transport::shadowsocks::guard::Shadowsocks;
use vortex_transport::shadowsocks::request::padding::MAX_PADDING;
use vortex_transport::shadowsocks::schedule::salt::{SessionSalt, SALT_LEN};
use vortex_transport::shadowsocks::session::Session;

#[pyclass(module = "vortex_chat", name = "Shadowsocks")]
pub struct PyShadowsocks {
    guard: Mutex<Shadowsocks>,
    random: Arc<dyn RandomSource>,
}

#[pymethods]
impl PyShadowsocks {
    #[new]
    #[pyo3(signature = (password, previous_password=""))]
    fn new(password: &str, previous_password: &str) -> Self {
        PyShadowsocks {
            guard: Mutex::new(Shadowsocks::new(
                password.as_bytes(),
                previous_password.as_bytes(),
            )),
            random: Arc::new(OsRandom::new()),
        }
    }

    #[pyo3(signature = (password, previous_password=""))]
    fn reload(&self, password: &str, previous_password: &str) {
        self.guard
            .lock()
            .reload(password.as_bytes(), previous_password.as_bytes());
    }

    fn add_password(&self, password: &str) -> bool {
        self.guard.lock().add_password(password.as_bytes())
    }

    #[pyo3(signature = (target_host, target_port, data=None))]
    fn connect(
        &self,
        target_host: &str,
        target_port: u16,
        data: Option<Vec<u8>>,
    ) -> PyResult<PyShadowsocksSession> {
        let data = data.unwrap_or_default();
        let handshake = self
            .guard
            .lock()
            .connect(target_host, target_port, &data, self.random.as_ref())
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(PyShadowsocksSession {
            prologue: Some(handshake.prologue().to_vec()),
            request: Some(handshake.request.clone()),
            stream: Some(handshake.stream()),
            destination: None,
            payload: None,
            consumed: 0,
            session: Mutex::new(handshake.session),
        })
    }

    fn connect_with(
        &self,
        target_host: &str,
        target_port: u16,
        data: &[u8],
        salt: &[u8],
        padding: &[u8],
    ) -> PyResult<PyShadowsocksSession> {
        let salt = SessionSalt::parse(salt).ok_or_else(|| bad_prologue(salt.len()))?;
        let handshake = self
            .guard
            .lock()
            .connect_with(target_host, target_port, data, salt, padding)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(PyShadowsocksSession {
            prologue: Some(handshake.prologue().to_vec()),
            request: Some(handshake.request.clone()),
            stream: Some(handshake.stream()),
            destination: None,
            payload: None,
            consumed: 0,
            session: Mutex::new(handshake.session),
        })
    }

    fn accept(&self, stream: &[u8]) -> (String, Option<PyShadowsocksSession>) {
        let verdict = self.guard.lock().accept(stream);
        let status = verdict.name().to_owned();
        let Some(accepted) = verdict.accepted() else {
            return (status, None);
        };
        (
            status,
            Some(PyShadowsocksSession {
                prologue: None,
                request: None,
                stream: None,
                destination: Some((accepted.host(), accepted.port())),
                payload: Some(accepted.payload),
                consumed: accepted.consumed,
                session: Mutex::new(accepted.session),
            }),
        )
    }

    fn client_config<'py>(
        &self,
        py: Python<'py>,
        server_host: &str,
        server_port: u16,
    ) -> PyResult<Bound<'py, PyDict>> {
        let profile = self.guard.lock().client_profile(server_host, server_port);
        let config = PyDict::new(py);
        config.set_item("protocol", profile.protocol)?;
        config.set_item("version", profile.version)?;
        config.set_item("server", profile.server)?;
        config.set_item("server_port", profile.server_port)?;
        config.set_item("cipher", profile.cipher)?;
        config.set_item("key_derivation", profile.key_derivation)?;
        Ok(config)
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
    fn authorized_count(&self) -> usize {
        self.guard.lock().accepted_count()
    }

    #[getter]
    fn prologue_len(&self) -> usize {
        SALT_LEN
    }

    #[getter]
    fn max_payload(&self) -> usize {
        MAX_PAYLOAD
    }

    #[getter]
    fn max_frame(&self) -> usize {
        MAX_FRAME
    }

    #[getter]
    fn max_padding(&self) -> usize {
        MAX_PADDING
    }

    #[getter]
    fn min_request_padding(&self) -> usize {
        self.guard.lock().config().min_padding
    }

    #[getter]
    fn max_request_padding(&self) -> usize {
        self.guard.lock().config().max_padding
    }

    fn status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let guard = self.guard.lock();
        let status = PyDict::new(py);
        status.set_item("protocol", "shadowsocks")?;
        status.set_item("version", 2)?;
        status.set_item("configured", guard.is_configured())?;
        status.set_item("accepts_previous", guard.accepts_previous())?;
        status.set_item("authorized_passwords", guard.accepted_count())?;
        status.set_item("prologue_len", SALT_LEN)?;
        status.set_item("max_payload", MAX_PAYLOAD)?;
        status.set_item("max_frame", MAX_FRAME)?;
        Ok(status)
    }
}

#[pyclass(module = "vortex_chat", name = "ShadowsocksSession")]
pub struct PyShadowsocksSession {
    prologue: Option<Vec<u8>>,
    request: Option<Vec<u8>>,
    stream: Option<Vec<u8>>,
    destination: Option<(String, u16)>,
    payload: Option<Vec<u8>>,
    consumed: usize,
    session: Mutex<Session>,
}

#[pymethods]
impl PyShadowsocksSession {
    #[getter]
    fn prologue<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.prologue.as_ref().map(|bytes| PyBytes::new(py, bytes))
    }

    #[getter]
    fn request<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.request.as_ref().map(|bytes| PyBytes::new(py, bytes))
    }

    #[getter]
    fn stream<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.stream.as_ref().map(|bytes| PyBytes::new(py, bytes))
    }

    #[getter]
    fn host(&self) -> Option<String> {
        self.destination.as_ref().map(|(host, _)| host.to_owned())
    }

    #[getter]
    fn port(&self) -> Option<u16> {
        self.destination.as_ref().map(|(_, port)| *port)
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.payload.as_ref().map(|bytes| PyBytes::new(py, bytes))
    }

    #[getter]
    fn consumed(&self) -> usize {
        self.consumed
    }

    fn seal<'py>(&self, py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
        let frames = self.session.lock().seal(data);
        PyBytes::new(py, &frames)
    }

    fn seal_one<'py>(&self, py: Python<'py>, body: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let frame = self
            .session
            .lock()
            .seal_one(body)
            .ok_or_else(|| body_out_of_range(body.len()))?;
        Ok(PyBytes::new(py, &frame))
    }

    fn open<'py>(&self, py: Python<'py>, buffer: &[u8]) -> Option<Bound<'py, PyBytes>> {
        self.session
            .lock()
            .open(buffer)
            .map(|data| PyBytes::new(py, &data))
    }

    fn drain<'py>(&self, py: Python<'py>, buffer: &[u8]) -> Option<(usize, Bound<'py, PyBytes>)> {
        self.session
            .lock()
            .drain(buffer)
            .map(|(consumed, data)| (consumed, PyBytes::new(py, &data)))
    }

    fn step(&self, buffer: &[u8]) -> PyShadowsocksFrameStep {
        match self.session.lock().step(buffer) {
            FrameStep::Opened { consumed, body } => PyShadowsocksFrameStep {
                status: "opened".to_owned(),
                consumed,
                body: Some(body),
            },
            other => PyShadowsocksFrameStep {
                status: other.name().to_owned(),
                consumed: 0,
                body: None,
            },
        }
    }

    #[getter]
    fn sealed_frames(&self) -> u64 {
        self.session.lock().sealed_frames()
    }

    #[getter]
    fn opened_frames(&self) -> u64 {
        self.session.lock().opened_frames()
    }
}

#[pyclass(module = "vortex_chat", name = "ShadowsocksFrameStep")]
pub struct PyShadowsocksFrameStep {
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    consumed: usize,
    body: Option<Vec<u8>>,
}

#[pymethods]
impl PyShadowsocksFrameStep {
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.body.as_ref().map(|bytes| PyBytes::new(py, bytes))
    }
}

fn bad_prologue(got: usize) -> PyErr {
    PyValueError::new_err(format!(
        "пролог должен быть длиной {SALT_LEN} байт, получено {got}"
    ))
}

fn body_out_of_range(got: usize) -> PyErr {
    PyValueError::new_err(format!(
        "тело кадра Shadowsocks должно быть от 1 до {MAX_PAYLOAD} байт, получено {got}"
    ))
}
