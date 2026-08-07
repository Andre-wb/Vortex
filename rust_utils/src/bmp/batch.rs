use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use vortex_bmp::service::outcome::BatchOutcome;

use crate::bmp::rejection::PyBmpRejection;

#[pyclass(module = "vortex_chat", name = "BmpBatch", frozen)]
pub struct PyBmpBatch {
    #[pyo3(get)]
    pub rejection: Option<PyBmpRejection>,
    #[pyo3(get)]
    pub mailboxes: Py<PyDict>,
    #[pyo3(get)]
    pub padding: String,
}

impl PyBmpBatch {
    pub fn rejected(py: Python<'_>, rejection: PyBmpRejection) -> PyResult<Self> {
        Ok(PyBmpBatch {
            rejection: Some(rejection),
            mailboxes: PyDict::new(py).unbind(),
            padding: String::new(),
        })
    }

    pub fn delivered(py: Python<'_>, outcome: BatchOutcome) -> PyResult<Self> {
        let mailboxes = PyDict::new(py);
        for (mailbox, messages) in outcome.mailboxes {
            let entries = PyList::empty(py);
            for message in messages {
                let entry = PyDict::new(py);
                entry.set_item("ct", message.ciphertext())?;
                entry.set_item("ts", message.bucketed_at())?;
                entries.append(entry)?;
            }
            mailboxes.set_item(mailbox.as_str(), entries)?;
        }
        Ok(PyBmpBatch {
            rejection: None,
            mailboxes: mailboxes.unbind(),
            padding: outcome.padding,
        })
    }
}

#[pymethods]
impl PyBmpBatch {
    fn __repr__(&self) -> String {
        match &self.rejection {
            Some(rejection) => format!("<BmpBatch rejected status={}>", rejection.status),
            None => "<BmpBatch delivered>".to_string(),
        }
    }
}
