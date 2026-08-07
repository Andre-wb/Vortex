use crate::http::body_policy::BodyPolicy;
use crate::python::response::PyWafResponse;
use pyo3::prelude::*;

#[pyclass(module = "vortex_waf", name = "BodyPlan", frozen)]
pub struct PyBodyPlan {
    policy: BodyPolicy,
}

impl PyBodyPlan {
    pub fn new(policy: BodyPolicy) -> Self {
        PyBodyPlan { policy }
    }
}

#[pymethods]
impl PyBodyPlan {
    #[getter]
    fn skip(&self) -> bool {
        self.policy.is_skip()
    }

    #[getter]
    fn read_body(&self) -> bool {
        self.policy.reads_body()
    }

    #[getter]
    fn body_limit(&self) -> usize {
        self.policy.body_limit()
    }

    #[getter]
    fn response(&self) -> Option<PyWafResponse> {
        self.policy.response().cloned().map(PyWafResponse::new)
    }

    fn __repr__(&self) -> String {
        format!(
            "<BodyPlan skip={} read_body={} limit={}>",
            self.policy.is_skip(),
            self.policy.reads_body(),
            self.policy.body_limit()
        )
    }
}
