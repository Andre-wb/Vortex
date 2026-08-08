use parking_lot::Mutex;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use vortex_transport::trojan::guard::Trojan;
use vortex_transport::trojan::request::decoder::MAX_REQUEST_HEADER_LEN;
use vortex_transport::trojan::request::incoming::Incoming;
use vortex_transport::trojan::secret::password_hash::PASSWORD_HASH_HEX_LEN;

#[pyclass(module = "vortex_chat", name = "Trojan")]
pub struct PyTrojan {
    guard: Mutex<Trojan>,
}

#[pymethods]
impl PyTrojan {
    #[new]
    #[pyo3(signature = (password, previous_password=""))]
    fn new(password: &str, previous_password: &str) -> Self {
        PyTrojan {
            guard: Mutex::new(Trojan::new(
                password.as_bytes(),
                previous_password.as_bytes(),
            )),
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

    #[pyo3(signature = (payload, target_addr="127.0.0.1", target_port=443))]
    fn encode_request<'py>(
        &self,
        py: Python<'py>,
        payload: &[u8],
        target_addr: &str,
        target_port: u16,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let request = self
            .guard
            .lock()
            .encode_request(target_addr, target_port, payload)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(PyBytes::new(py, &request))
    }

    fn decode_request(&self, data: &[u8]) -> Option<PyTrojanRequest> {
        self.guard
            .lock()
            .decode_request(data)
            .accepted()
            .map(PyTrojanRequest::from)
    }

    fn inspect(&self, data: &[u8]) -> String {
        self.guard.lock().decode_request(data).name().to_owned()
    }

    fn probe(&self, data: &[u8]) -> String {
        self.guard.lock().probe(data).name().to_owned()
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
    fn password_hash(&self) -> Option<String> {
        self.guard.lock().password_hash().map(|hash| hash.to_hex())
    }

    #[getter]
    fn password_hash_len(&self) -> usize {
        PASSWORD_HASH_HEX_LEN
    }

    #[getter]
    fn max_request_header_len(&self) -> usize {
        MAX_REQUEST_HEADER_LEN
    }

    fn status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let guard = self.guard.lock();
        let status = PyDict::new(py);
        status.set_item("protocol", "trojan")?;
        status.set_item("authorized_passwords", guard.accepted_count())?;
        status.set_item("configured", guard.is_configured())?;
        status.set_item("accepts_previous", guard.accepts_previous())?;
        status.set_item("fallback", "nginx_cover_site")?;
        Ok(status)
    }
}

#[pyclass(module = "vortex_chat", name = "TrojanRequest")]
pub struct PyTrojanRequest {
    password_hash: String,
    command: &'static str,
    address_type: &'static str,
    host: String,
    port: u16,
    payload: Vec<u8>,
}

impl From<Incoming> for PyTrojanRequest {
    fn from(incoming: Incoming) -> Self {
        PyTrojanRequest {
            password_hash: incoming.hash.to_hex(),
            command: incoming.header.command.name(),
            address_type: incoming.header.destination.address.kind_name(),
            host: incoming.host(),
            port: incoming.port(),
            payload: incoming.payload,
        }
    }
}

#[pymethods]
impl PyTrojanRequest {
    #[getter]
    fn password_hash(&self) -> &str {
        &self.password_hash
    }

    #[getter]
    fn command(&self) -> &str {
        self.command
    }

    #[getter]
    fn address_type(&self) -> &str {
        self.address_type
    }

    #[getter]
    fn host(&self) -> &str {
        &self.host
    }

    #[getter]
    fn port(&self) -> u16 {
        self.port
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.payload)
    }

    fn __repr__(&self) -> String {
        format!(
            "TrojanRequest(command={}, host={}, port={}, payload={} байт)",
            self.command,
            self.host,
            self.port,
            self.payload.len()
        )
    }
}
