use pyo3::prelude::*;
use vortex_bmp::rejection::Rejection;

#[pyclass(module = "vortex_chat", name = "BmpRejection", frozen)]
#[derive(Clone)]
pub struct PyBmpRejection {
    #[pyo3(get)]
    pub status: u16,
    #[pyo3(get)]
    pub detail: String,
}

impl PyBmpRejection {
    pub fn new(rejection: Rejection) -> Self {
        PyBmpRejection {
            status: rejection.status,
            detail: rejection.detail,
        }
    }
}

#[pymethods]
impl PyBmpRejection {
    fn __repr__(&self) -> String {
        format!(
            "<BmpRejection status={} detail={}>",
            self.status, self.detail
        )
    }
}
