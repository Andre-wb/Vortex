use parking_lot::Mutex;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_transport::naive::client::profile::ClientProfile;
use vortex_transport::naive::config::{NaiveConfig, DEFAULT_PORT};
use vortex_transport::naive::guard::Naive;

#[pyclass(module = "vortex_chat", name = "Naive")]
pub struct PyNaive {
    guard: Mutex<Naive>,
}

#[pymethods]
impl PyNaive {
    #[new]
    #[pyo3(signature = (port=DEFAULT_PORT, backend_url="", server_host=""))]
    fn new(port: u16, backend_url: &str, server_host: &str) -> Self {
        PyNaive {
            guard: Mutex::new(Naive::new(NaiveConfig::new(port, backend_url, server_host))),
        }
    }

    fn reload(&self, username: &str, password: &str, probe_domain: &str) {
        self.guard.lock().reload(username, password, probe_domain);
    }

    #[pyo3(signature = (username="", password="", email="", probe_domain=""))]
    fn caddyfile(
        &self,
        username: &str,
        password: &str,
        email: &str,
        probe_domain: &str,
    ) -> PyResult<String> {
        self.guard
            .lock()
            .caddyfile(username, password, email, probe_domain)
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    #[pyo3(signature = (server_host="", username="", password=""))]
    fn proxy_url(&self, server_host: &str, username: &str, password: &str) -> PyResult<String> {
        self.guard
            .lock()
            .proxy_url(server_host, username, password)
            .map(|url| url.as_str().to_owned())
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    #[pyo3(signature = (server_host="", username="", password=""))]
    fn client_config<'py>(
        &self,
        py: Python<'py>,
        server_host: &str,
        username: &str,
        password: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let profile = self
            .guard
            .lock()
            .client_profile(server_host, username, password)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        into_dict(py, &profile)
    }

    #[getter]
    fn port(&self) -> u16 {
        self.guard.lock().config().port
    }

    #[getter]
    fn backend_url(&self) -> String {
        self.guard.lock().config().upstream_or_default().to_owned()
    }

    #[getter]
    fn server_host(&self) -> String {
        self.guard.lock().config().server_host.clone()
    }

    #[getter]
    fn username(&self) -> String {
        self.guard.lock().username().to_owned()
    }

    #[getter]
    fn password(&self) -> String {
        self.guard.lock().password().to_owned()
    }

    #[getter]
    fn probe_domain(&self) -> String {
        self.guard.lock().probe_domain().to_owned()
    }

    #[getter]
    fn is_renderable(&self) -> bool {
        self.guard.lock().is_renderable()
    }

    fn status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let guard = self.guard.lock();
        let host = guard.config().server_host.clone();
        let status = PyDict::new(py);
        status.set_item("protocol", "naiveproxy")?;
        status.set_item("port", guard.config().port)?;
        status.set_item(
            "server_host",
            if host.is_empty() {
                "not_configured".to_owned()
            } else {
                host
            },
        )?;
        status.set_item("fingerprint", "chrome_identical")?;
        Ok(status)
    }
}

fn into_dict<'py>(py: Python<'py>, profile: &ClientProfile) -> PyResult<Bound<'py, PyDict>> {
    let config = PyDict::new(py);
    config.set_item("listen", &profile.listen)?;
    config.set_item("proxy", profile.proxy.as_str())?;
    config.set_item("log", &profile.log)?;
    config.set_item("padding", profile.padding)?;
    Ok(config)
}
