use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_proto::key::client_device_id::CLIENT_DEVICE_ID_LEN;
use vortex_proto::key::ed25519_public::ED25519_PUBLIC_LEN;
use vortex_proto::key::ed25519_signature::ED25519_SIGNATURE_LEN;
use vortex_proto::key::kyber_public::KYBER_PUBLIC_LEN;
use vortex_proto::key::x25519_public::X25519_PUBLIC_LEN;
use vortex_proto::prekey::limits::{LOW_ONE_TIME_THRESHOLD, MAX_ONE_TIME_BATCH};

pub fn limits_dict(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("max_one_time_batch", MAX_ONE_TIME_BATCH)?;
    out.set_item("low_one_time_threshold", LOW_ONE_TIME_THRESHOLD)?;
    out.set_item("client_device_id_len", CLIENT_DEVICE_ID_LEN)?;
    out.set_item("x25519_public_hex_len", X25519_PUBLIC_LEN * 2)?;
    out.set_item("ed25519_public_hex_len", ED25519_PUBLIC_LEN * 2)?;
    out.set_item("ed25519_signature_hex_len", ED25519_SIGNATURE_LEN * 2)?;
    out.set_item("kyber_public_hex_len", KYBER_PUBLIC_LEN * 2)?;
    Ok(out)
}
