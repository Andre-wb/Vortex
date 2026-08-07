use crate::http::responses::http_response::HttpResponse;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass(module = "vortex_waf", name = "WafResponse", frozen)]
pub struct PyWafResponse {
    response: HttpResponse,
}

impl PyWafResponse {
    pub fn new(response: HttpResponse) -> Self {
        PyWafResponse { response }
    }
}

#[pymethods]
impl PyWafResponse {
    #[getter]
    fn status(&self) -> u16 {
        self.response.status
    }

    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> Vec<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        self.response
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    PyBytes::new(py, name.as_bytes()),
                    PyBytes::new(py, value.as_bytes()),
                )
            })
            .collect()
    }

    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.response.body)
    }

    fn __repr__(&self) -> String {
        format!(
            "<WafResponse {} {} байт>",
            self.response.status,
            self.response.body.len()
        )
    }
}
