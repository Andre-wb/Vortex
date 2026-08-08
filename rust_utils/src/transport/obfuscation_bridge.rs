use parking_lot::Mutex;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::sync::Arc;
use vortex_transport::obfuscation::guard::Obfuscation;
use vortex_transport::obfuscation::normalizer::config::NormalizerConfig;
use vortex_transport::obfuscation::normalizer::traffic;
use vortex_transport::obfuscation::padding::web_sizes::WEB_SIZES;
use vortex_transport::obfuscation::timing::interval::DEFAULT_JITTER_RATIO;
use vortex_transport::ports::random_source::RandomSource;
use vortex_transport::random::os_random::OsRandom;
use vortex_transport::vortex_obfs::config::VortexObfsConfig;
use vortex_transport::vortex_obfs::frame::limits::{MAX_FRAME, MAX_PADDING, MAX_PAYLOAD};
use vortex_transport::vortex_obfs::frame::step::FrameStep;
use vortex_transport::vortex_obfs::guard::VortexObfs;
use vortex_transport::vortex_obfs::schedule::salt::{SessionSalt, SALT_LEN};
use vortex_transport::vortex_obfs::session::Session;

#[pyclass(module = "vortex_chat", name = "Obfuscation")]
pub struct PyObfuscation {
    guard: Obfuscation,
    random: Arc<dyn RandomSource>,
}

#[pymethods]
impl PyObfuscation {
    #[new]
    fn new() -> Self {
        PyObfuscation {
            guard: Obfuscation::default(),
            random: Arc::new(OsRandom::new()),
        }
    }

    #[pyo3(signature = (data, targets=None))]
    fn pad<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        targets: Option<Vec<usize>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let envelope = self
            .guard
            .pad(data, targets.as_deref(), self.random.as_ref())
            .ok_or_else(|| too_long(data.len()))?;
        Ok(PyBytes::new(py, &envelope))
    }

    fn pad_with<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        padding: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let envelope = self
            .guard
            .pad_with(data, padding)
            .ok_or_else(|| too_long(data.len().max(padding.len())))?;
        Ok(PyBytes::new(py, &envelope))
    }

    fn unpad<'py>(&self, py: Python<'py>, envelope: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.guard.unpad(envelope).ok_or_else(|| {
            PyValueError::new_err(format!(
                "буфер длиной {} байт не является конвертом обфускации",
                envelope.len()
            ))
        })?;
        Ok(PyBytes::new(py, data))
    }

    fn delay(&self) -> f64 {
        self.guard.delay(self.random.as_ref())
    }

    fn is_worth_waiting(&self, seconds: f64) -> bool {
        self.guard.is_worth_waiting(seconds)
    }

    #[pyo3(signature = (base, jitter_ratio=DEFAULT_JITTER_RATIO))]
    fn interval(&self, base: f64, jitter_ratio: f64) -> f64 {
        self.guard
            .interval(base, jitter_ratio, self.random.as_ref())
    }

    fn cover_headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let headers = PyDict::new(py);
        for (name, value) in self.guard.cover_headers() {
            headers.set_item(name, value)?;
        }
        Ok(headers)
    }

    #[getter]
    fn web_sizes(&self) -> Vec<usize> {
        WEB_SIZES.to_vec()
    }

    #[getter]
    fn min_padding(&self) -> usize {
        self.guard.padding_config().min
    }

    #[getter]
    fn max_padding(&self) -> usize {
        self.guard.padding_config().max
    }

    #[getter]
    fn delay_ceiling(&self) -> f64 {
        self.guard.delay_config().ceiling
    }
}

#[pyclass(module = "vortex_chat", name = "TrafficNormalizer")]
pub struct PyTrafficNormalizer {
    inner: Mutex<traffic::TrafficNormalizer>,
}

#[pymethods]
impl PyTrafficNormalizer {
    #[new]
    #[pyo3(signature = (target_kbps=NormalizerConfig::default().target_kbps))]
    fn new(target_kbps: f64) -> Self {
        PyTrafficNormalizer {
            inner: Mutex::new(traffic::TrafficNormalizer::new(NormalizerConfig::new(
                target_kbps,
            ))),
        }
    }

    fn record_sent(&self, now: f64, nbytes: usize) {
        self.inner.lock().record_sent(now, nbytes);
    }

    fn padding_needed(&self, now: f64) -> usize {
        self.inner.lock().padding_needed(now)
    }

    #[getter]
    fn target_kbps(&self) -> f64 {
        self.inner.lock().config().target_kbps
    }

    #[getter]
    fn target_bytes_per_sec(&self) -> f64 {
        self.inner.lock().config().bytes_per_second()
    }

    #[getter]
    fn max_chunk(&self) -> usize {
        self.inner.lock().config().max_chunk
    }
}

#[pyclass(module = "vortex_chat", name = "ObfuscationFrames")]
pub struct PyObfuscationFrames {
    guard: Arc<VortexObfs>,
    random: Arc<dyn RandomSource>,
}

#[pymethods]
impl PyObfuscationFrames {
    #[new]
    #[pyo3(signature = (secret=None))]
    fn new(secret: Option<Vec<u8>>) -> Self {
        PyObfuscationFrames {
            guard: Arc::new(VortexObfs::new(&secret.unwrap_or_default())),
            random: Arc::new(OsRandom::new()),
        }
    }

    #[getter]
    fn is_configured(&self) -> bool {
        self.guard.is_configured()
    }

    fn begin(&self) -> PyResult<PyObfuscationSession> {
        let handshake = self
            .guard
            .begin(self.random.as_ref())
            .ok_or_else(unconfigured)?;
        Ok(PyObfuscationSession {
            prologue: Some(handshake.salt.as_bytes().to_vec()),
            session: Mutex::new(handshake.session),
            config: *self.guard.config(),
            random: self.random.clone(),
        })
    }

    fn begin_with_salt(&self, salt: &[u8]) -> PyResult<PyObfuscationSession> {
        let salt = SessionSalt::parse(salt).ok_or_else(|| bad_prologue(salt.len()))?;
        let handshake = self.guard.begin_with_salt(salt).ok_or_else(unconfigured)?;
        Ok(PyObfuscationSession {
            prologue: Some(handshake.salt.as_bytes().to_vec()),
            session: Mutex::new(handshake.session),
            config: *self.guard.config(),
            random: self.random.clone(),
        })
    }

    fn accept(&self, prologue: &[u8]) -> PyResult<PyObfuscationSession> {
        if prologue.len() != SALT_LEN {
            return Err(bad_prologue(prologue.len()));
        }
        let session = self.guard.accept(prologue).ok_or_else(unconfigured)?;
        Ok(PyObfuscationSession {
            prologue: None,
            session: Mutex::new(session),
            config: *self.guard.config(),
            random: self.random.clone(),
        })
    }

    #[getter]
    fn prologue_len(&self) -> usize {
        SALT_LEN
    }

    fn status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let status = PyDict::new(py);
        status.set_item("protocol", "vortex_obfs")?;
        status.set_item("version", 2)?;
        status.set_item("configured", self.guard.is_configured())?;
        status.set_item("prologue_len", SALT_LEN)?;
        status.set_item("max_payload", MAX_PAYLOAD)?;
        status.set_item("max_frame", MAX_FRAME)?;
        Ok(status)
    }
}

#[pyclass(module = "vortex_chat", name = "ObfuscationSession")]
pub struct PyObfuscationSession {
    prologue: Option<Vec<u8>>,
    session: Mutex<Session>,
    config: VortexObfsConfig,
    random: Arc<dyn RandomSource>,
}

#[pymethods]
impl PyObfuscationSession {
    #[getter]
    fn prologue<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.prologue.as_ref().map(|bytes| PyBytes::new(py, bytes))
    }

    fn wrap<'py>(&self, py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
        let frames = self
            .session
            .lock()
            .wrap(data, &self.config, self.random.as_ref());
        PyBytes::new(py, &frames)
    }

    fn wrap_one<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        padding: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let frame = self
            .session
            .lock()
            .wrap_one(data, padding)
            .ok_or_else(|| frame_too_long(data.len(), padding.len()))?;
        Ok(PyBytes::new(py, &frame))
    }

    fn unwrap<'py>(&self, py: Python<'py>, buffer: &[u8]) -> Option<Bound<'py, PyBytes>> {
        self.session
            .lock()
            .unwrap(buffer)
            .map(|data| PyBytes::new(py, &data))
    }

    fn drain<'py>(&self, py: Python<'py>, buffer: &[u8]) -> Option<(usize, Bound<'py, PyBytes>)> {
        self.session
            .lock()
            .drain(buffer)
            .map(|(consumed, data)| (consumed, PyBytes::new(py, &data)))
    }

    fn step(&self, buffer: &[u8]) -> PyObfuscationFrameStep {
        match self.session.lock().step(buffer) {
            FrameStep::Opened { consumed, data } => PyObfuscationFrameStep {
                status: "opened".to_owned(),
                consumed,
                data: Some(data),
            },
            other => PyObfuscationFrameStep {
                status: other.name().to_owned(),
                consumed: 0,
                data: None,
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

#[pyclass(module = "vortex_chat", name = "ObfuscationFrameStep")]
pub struct PyObfuscationFrameStep {
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    consumed: usize,
    data: Option<Vec<u8>>,
}

#[pymethods]
impl PyObfuscationFrameStep {
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.data.as_ref().map(|bytes| PyBytes::new(py, bytes))
    }
}

fn unconfigured() -> PyErr {
    PyValueError::new_err("общий секрет обфускации не задан: кадр собрать нечем")
}

fn bad_prologue(got: usize) -> PyErr {
    PyValueError::new_err(format!(
        "пролог должен быть длиной {SALT_LEN} байт, получено {got}"
    ))
}

fn too_long(got: usize) -> PyErr {
    PyValueError::new_err(format!(
        "сообщение не помещается в конверт обфускации: {got} байт"
    ))
}

fn frame_too_long(data: usize, padding: usize) -> PyErr {
    PyValueError::new_err(format!(
        "кадр длиннее предела: {data} байт данных при пределе {MAX_PAYLOAD}, {padding} байт паддинга при пределе {MAX_PADDING}"
    ))
}
