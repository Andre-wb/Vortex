use pyo3::prelude::*;
use pyo3::types::PyBytes;
use blake3;

#[pyfunction]
fn hash_string(data: String) -> String {
    let hash = blake3::hash(data.as_bytes());
    hash.to_hex().to_string()
}

#[pyfunction]
fn hash_bytes(data: &Bound<'_, PyBytes>) -> PyResult<String> {
    let bytes = data.as_bytes();
    let hash = blake3::hash(bytes);
    Ok(hash.to_hex().to_string())
}

#[pyfunction]
fn xor_encrypt(py: Python<'_>, data: &Bound<'_, PyBytes>, key: u8) -> PyResult<Py<PyBytes>> {
    let bytes = data.as_bytes();
    let result: Vec<u8> = bytes.iter()
        .map(|&byte| byte ^ key)
        .collect();

    let bound_bytes = PyBytes::new(py, &result);
    Ok(bound_bytes.unbind())
}

#[pyclass]
struct P2PNode {
    node_id: String,
    peers: Vec<String>,
}

#[pymethods]
impl P2PNode {
    #[new]
    fn new(node_id: String) -> Self {
        P2PNode {
            node_id,
            peers: Vec::new(),
        }
    }

    fn add_peer(&mut self, peer: String) {
        self.peers.push(peer);
    }

    fn get_peers(&self) -> Vec<String> {
        self.peers.clone()
    }

    fn node_info(&self) -> String {
        format!("Node {} has {} peers", self.node_id, self.peers.len())
    }
}

#[pymodule]
fn vortex(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_string, m)?)?;
    m.add_function(wrap_pyfunction!(hash_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(xor_encrypt, m)?)?;

    m.add_class::<P2PNode>()?;
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}