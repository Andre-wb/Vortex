use pyo3::prelude::*;
use vortex_storage::prekey::bundle::record::BundleRecord;

use crate::proto::stored::PyStoredBundle;

#[pyclass(module = "vortex_chat", name = "StoredBundleRecord", frozen)]
pub struct PyBundleRecord {
    pub inner: BundleRecord,
}

impl PyBundleRecord {
    pub fn new(inner: BundleRecord) -> PyBundleRecord {
        PyBundleRecord { inner }
    }
}

#[pymethods]
impl PyBundleRecord {
    #[getter]
    fn id(&self) -> i64 {
        self.inner.id
    }

    #[getter]
    fn user_id(&self) -> i64 {
        self.inner.user_id
    }

    #[getter]
    fn bundle(&self) -> PyStoredBundle {
        PyStoredBundle {
            inner: self.inner.bundle.clone(),
        }
    }

    #[getter]
    fn created_at(&self) -> (i64, u32) {
        (
            self.inner.created_at.unix_seconds(),
            self.inner.created_at.micros(),
        )
    }

    #[getter]
    fn updated_at(&self) -> (i64, u32) {
        (
            self.inner.updated_at.unix_seconds(),
            self.inner.updated_at.micros(),
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "<StoredBundleRecord id={} user_id={}>",
            self.inner.id, self.inner.user_id
        )
    }
}
