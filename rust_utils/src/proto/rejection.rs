use pyo3::prelude::*;
use vortex_proto::reject::rejection::Rejection;

#[pyclass(module = "vortex_chat", name = "ProtoRejection", frozen)]
#[derive(Clone)]
pub struct PyProtoRejection {
    #[pyo3(get)]
    pub status: u16,
    #[pyo3(get)]
    pub detail: String,
}

impl PyProtoRejection {
    pub fn new(rejection: Rejection) -> Self {
        PyProtoRejection {
            status: rejection.status,
            detail: rejection.detail,
        }
    }
}

#[pymethods]
impl PyProtoRejection {
    fn __repr__(&self) -> String {
        format!(
            "<ProtoRejection status={} detail={}>",
            self.status, self.detail
        )
    }
}
