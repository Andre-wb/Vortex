use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::{Digest, Sha256};

#[pyfunction]
pub fn sha256_hex(py: Python<'_>, data: &[u8]) -> PyResult<String> {
    let d = data.to_vec();
    let hex = py.allow_threads(move || {
        let mut h = Sha256::new();
        h.update(&d);
        hex::encode(h.finalize())
    });
    Ok(hex)
}

#[pyfunction]
pub fn sha256_concat_hex(py: Python<'_>, chunks: Vec<Vec<u8>>) -> PyResult<Vec<String>> {
    use rayon::prelude::*;
    let out = py.allow_threads(move || {
        chunks
            .par_iter()
            .map(|c| {
                let mut h = Sha256::new();
                h.update(c);
                hex::encode(h.finalize())
            })
            .collect()
    });
    Ok(out)
}

#[pyfunction]
pub fn sha256_combine_hex(py: Python<'_>, hex_list: Vec<String>) -> PyResult<String> {
    let hl = hex_list;
    let hex = py.allow_threads(move || {
        let mut h = Sha256::new();
        for s in &hl {
            h.update(s.as_bytes());
        }
        hex::encode(h.finalize())
    });
    Ok(hex)
}

#[pyfunction]
pub fn sha256_stream(_py: Python<'_>, data: Bound<'_, PyBytes>) -> PyResult<(String, usize)> {
    let slice = data.as_bytes();
    let len = slice.len();
    let mut h = Sha256::new();
    h.update(slice);
    Ok((hex::encode(h.finalize()), len))
}
