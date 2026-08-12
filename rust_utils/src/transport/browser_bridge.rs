use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Mutex;
use vortex_transport::cookie::jar::CookieJar;
use vortex_transport::headers::{chrome, order};
use vortex_transport::random::os_random::OsRandom;
use vortex_transport::referer::chain::RefererChain;

#[pyfunction]
pub fn header_order(fields: Vec<(String, String)>) -> Vec<(String, String)> {
    order::arrange(&fields)
}

#[pyfunction]
#[pyo3(signature = (host, path="/", referer="", cookies=""))]
pub fn chrome_headers(
    host: &str,
    path: &str,
    referer: &str,
    cookies: &str,
) -> Vec<(String, String)> {
    let _ = path;
    chrome::navigation(host, referer, cookies)
}

#[pyclass(module = "vortex_chat", name = "CookieJar")]
pub struct PyCookieJar {
    jar: Mutex<CookieJar>,
    random: OsRandom,
}

#[pymethods]
impl PyCookieJar {
    #[new]
    fn new(now: i64) -> Self {
        let random = OsRandom::new();
        PyCookieJar {
            jar: Mutex::new(CookieJar::opened(&random, now)),
            random,
        }
    }

    fn header(&self, now: i64) -> String {
        self.jar.lock().unwrap().header(&self.random, now)
    }

    fn rotate(&self, now: i64) {
        self.jar.lock().unwrap().rotate(&self.random, now);
    }
}

#[pyclass(module = "vortex_chat", name = "RefererChain")]
pub struct PyRefererChain {
    chain: Mutex<RefererChain>,
    random: OsRandom,
}

#[pymethods]
impl PyRefererChain {
    #[new]
    fn new(site: &str) -> Self {
        let random = OsRandom::new();
        PyRefererChain {
            chain: Mutex::new(RefererChain::starting_at(site, &random)),
            random,
        }
    }

    #[pyo3(signature = (depth=None))]
    fn referer(&self, depth: Option<usize>) -> String {
        let chain = self.chain.lock().unwrap();
        match depth {
            Some(step) => chain.referer(step).to_owned(),
            None => chain.entry_referer(&self.random).to_owned(),
        }
    }

    fn advance(&self) {
        self.chain.lock().unwrap().advance(&self.random);
    }

    fn steps(&self) -> Vec<String> {
        self.chain.lock().unwrap().steps().to_vec()
    }
}

#[pyclass(module = "vortex_chat", name = "EntropyEnvelope", frozen)]
pub struct PyEntropyEnvelope;

#[pymethods]
impl PyEntropyEnvelope {
    #[staticmethod]
    fn wrap(payload: &[u8]) -> Vec<u8> {
        vortex_transport::entropy::envelope::wrap(payload)
    }

    #[staticmethod]
    fn unwrap(envelope: &[u8]) -> Option<Vec<u8>> {
        vortex_transport::entropy::envelope::unwrap(envelope)
    }

    #[staticmethod]
    fn headers(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
        let out = PyDict::new(py);
        for (name, value) in vortex_transport::entropy::headers::describing() {
            out.set_item(name, value)?;
        }
        Ok(out)
    }
}
