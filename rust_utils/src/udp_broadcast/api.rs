use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vortex_net::net::subnet_broadcast;
use vortex_net::random::OsRandom;
use vortex_net::stealth;
use vortex_net::stealth::NONCE_LEN;
use vortex_net::wire;

#[pyfunction]
#[pyo3(signature = (name, port, pubkey=None))]
pub fn udp_encode<'py>(
    py: Python<'py>,
    name: &str,
    port: u16,
    pubkey: Option<&str>,
) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &wire::encode(name, port, pubkey))
}

#[pyfunction]
pub fn udp_decode(
    data: &[u8],
    fallback_name: &str,
    fallback_port: u16,
) -> Option<(String, u16, Option<String>)> {
    wire::decode(data, fallback_name, fallback_port)
        .map(|decoded| (decoded.name, decoded.port, decoded.pubkey))
}

#[pyfunction]
pub fn udp_stealth_seal<'py>(
    py: Python<'py>,
    payload: &[u8],
    network_key: &[u8],
    nonce: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("nonce должен быть длиной {NONCE_LEN} байт")))?;
    Ok(PyBytes::new(
        py,
        &stealth::seal(payload, &nonce, network_key),
    ))
}

#[pyfunction]
pub fn udp_stealth_seal_random<'py>(
    py: Python<'py>,
    payload: &[u8],
    network_key: &[u8],
) -> Bound<'py, PyBytes> {
    let sealed = stealth::seal_with(payload, &OsRandom::new(), network_key);
    PyBytes::new(py, &sealed)
}

#[pyfunction]
pub fn udp_stealth_open<'py>(
    py: Python<'py>,
    data: &[u8],
    network_key: &[u8],
) -> Option<Bound<'py, PyBytes>> {
    stealth::open(data, network_key).map(|opened| PyBytes::new(py, &opened))
}

#[pyfunction]
pub fn udp_stealth_port() -> u16 {
    stealth::stealth_udp_port(&OsRandom::new())
}

#[pyfunction]
pub fn udp_subnet_broadcast(ip: &str) -> String {
    subnet_broadcast(ip)
}
