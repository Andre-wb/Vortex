use crate::http::guard::WafGuard;
use crate::http::request_head::RequestHead;
use crate::interop::raw_request_spec::RawRequestSpec;
use crate::python::body_plan::PyBodyPlan;
use crate::python::response::PyWafResponse;
use pyo3::prelude::*;

#[pyclass(module = "vortex_waf", name = "WafGuard", frozen)]
pub struct PyWafGuard {
    guard: WafGuard,
}

impl PyWafGuard {
    pub fn new(guard: WafGuard) -> Self {
        PyWafGuard { guard }
    }
}

#[pymethods]
impl PyWafGuard {
    #[pyo3(signature = (method, path, content_length=None))]
    fn plan(&self, method: &str, path: &str, content_length: Option<usize>) -> PyBodyPlan {
        let head = RequestHead {
            method: method.to_owned(),
            path: path.to_owned(),
            content_length,
        };
        PyBodyPlan::new(self.guard.plan(&head))
    }

    #[pyo3(signature = (method, path, query_string, headers, peer=None, content_length=None, body=None))]
    fn evaluate(
        &self,
        method: String,
        path: String,
        query_string: Vec<u8>,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        peer: Option<String>,
        content_length: Option<usize>,
        body: Option<Vec<u8>>,
    ) -> Option<PyWafResponse> {
        let spec = RawRequestSpec {
            method,
            path,
            query_string,
            headers,
            peer,
            content_length,
            body: body.unwrap_or_default(),
        };
        self.guard
            .evaluate(&spec.into_raw_request())
            .response()
            .cloned()
            .map(PyWafResponse::new)
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.guard.excluded_paths().contains(path)
    }

    #[getter]
    fn max_body_bytes(&self) -> usize {
        self.guard.max_body_bytes()
    }

    fn __repr__(&self) -> String {
        format!(
            "<WafGuard max_body_bytes={} excluded_paths={}>",
            self.guard.max_body_bytes(),
            self.guard.excluded_paths().len()
        )
    }
}
