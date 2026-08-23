use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_proto::wrap::envelope::WrappedKey;
use vortex_proto::wrap::render::WrapView;
use vortex_proto::wrap::request::WrapRequest;

#[pyclass(module = "vortex_chat", name = "WrappedKey", frozen)]
pub struct PyWrappedKey {
    view: WrapView,
}

#[pymethods]
impl PyWrappedKey {
    #[getter]
    fn hybrid(&self) -> bool {
        self.view.hybrid
    }

    #[getter]
    fn ephemeral_pub(&self) -> &str {
        &self.view.ephemeral_pub
    }

    #[getter]
    fn kyber_ciphertext(&self) -> Option<&str> {
        self.view.kyber_ciphertext.as_deref()
    }

    #[getter]
    fn ciphertext(&self) -> &str {
        &self.view.ciphertext
    }

    fn client_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        view_dict(py, &self.view)
    }

    fn __repr__(&self) -> String {
        format!("<WrappedKey hybrid={}>", self.view.hybrid)
    }
}

pub fn view_dict<'py>(py: Python<'py>, view: &WrapView) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    if view.hybrid {
        out.set_item("hybrid", true)?;
        out.set_item("x25519_ephemeral_pub", &view.ephemeral_pub)?;
        out.set_item("kyber_ciphertext", &view.kyber_ciphertext)?;
    } else {
        out.set_item("ephemeral_pub", &view.ephemeral_pub)?;
    }
    out.set_item("ciphertext", &view.ciphertext)?;
    Ok(out)
}

#[pyfunction]
pub fn wrapped_key_parse(payload: &str) -> Option<PyWrappedKey> {
    let request = WrapRequest::from_json(payload).ok()?;
    let wrapped = WrappedKey::parse(&request).ok()?;
    Some(PyWrappedKey {
        view: WrapView::of(&wrapped),
    })
}

#[pyfunction]
#[pyo3(signature = (ephemeral_pub, ciphertext, kyber_ciphertext=None))]
pub fn wrapped_key_stored<'py>(
    py: Python<'py>,
    ephemeral_pub: &str,
    ciphertext: &str,
    kyber_ciphertext: Option<&str>,
) -> PyResult<Bound<'py, PyDict>> {
    view_dict(
        py,
        &WrapView::stored(ephemeral_pub, ciphertext, kyber_ciphertext),
    )
}
