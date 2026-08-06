use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use super::hybrid::combine;
use super::mlkem768::{codec, decaps, encaps, keygen};

#[pyfunction]
pub fn mlkem768_keygen() -> (Vec<u8>, Vec<u8>) {
    keygen::keygen()
}

#[pyfunction]
pub fn mlkem768_encapsulate(public_key: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    encaps::encapsulate(&public_key).map_err(PyValueError::new_err)
}

#[pyfunction]
pub fn mlkem768_decapsulate(secret_key: Vec<u8>, ciphertext: Vec<u8>) -> PyResult<Vec<u8>> {
    decaps::decapsulate(&secret_key, &ciphertext).map_err(PyValueError::new_err)
}

#[pyfunction]
pub fn mlkem768_keygen_derand(d: Vec<u8>, z: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let d = codec::seed(&d, "d").map_err(PyValueError::new_err)?;
    let z = codec::seed(&z, "z").map_err(PyValueError::new_err)?;
    Ok(keygen::keygen_derand(&d, &z))
}

#[pyfunction]
pub fn mlkem768_encapsulate_derand(
    public_key: Vec<u8>,
    m: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let m = codec::seed(&m, "m").map_err(PyValueError::new_err)?;
    encaps::encapsulate_derand(&public_key, &m).map_err(PyValueError::new_err)
}

#[pyfunction]
pub fn pq_hybrid_combine(x25519_shared: Vec<u8>, kyber_shared: Vec<u8>, info: Vec<u8>) -> Vec<u8> {
    combine::combine(&x25519_shared, &kyber_shared, &info).to_vec()
}
