use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_proto::key::client_device_id::ClientDeviceId;
use vortex_proto::prekey::bundle::render::{bundle_list, bundle_response};
use vortex_proto::prekey::claim::response::ClaimResponse;
use vortex_proto::prekey::publish::parse;
use vortex_proto::prekey::publish::request::PublishRequest;
use vortex_proto::prekey::status::report::StatusReport;
use vortex_proto::reject::rejection::Rejection;
use vortex_proto::verify::dalek::DalekVerifier;
use vortex_proto::verify::enforcement::Enforcement;

use crate::proto::bundle;
use crate::proto::limits;
use crate::proto::publish::PyPreKeyPublish;
use crate::proto::rejection::PyProtoRejection;
use crate::proto::stored::PyStoredBundle;

#[pyfunction]
pub fn prekey_parse_publish(payload: &str, enforce: bool) -> PyPreKeyPublish {
    let request = match PublishRequest::from_json(payload) {
        Ok(value) => value,
        Err(_) => {
            return PyPreKeyPublish::refused(PyProtoRejection::new(Rejection::bad_request(
                "Malformed pre-key publish payload",
            )))
        }
    };

    match parse(&request, Enforcement::from_flag(enforce), &DalekVerifier) {
        Ok(parsed) => PyPreKeyPublish::accepted(parsed),
        Err(rejection) => PyPreKeyPublish::refused(PyProtoRejection::new(rejection)),
    }
}

#[pyfunction]
pub fn prekey_bundle_response<'py>(
    py: Python<'py>,
    user_id: i64,
    stored: &PyStoredBundle,
) -> PyResult<Bound<'py, PyDict>> {
    bundle::bundle_response_dict(py, &bundle_response(user_id, &stored.inner))
}

#[pyfunction]
pub fn prekey_bundle_list<'py>(
    py: Python<'py>,
    user_id: i64,
    stored: Vec<PyRef<'py, PyStoredBundle>>,
) -> PyResult<Bound<'py, PyDict>> {
    let bundles: Vec<_> = stored.iter().map(|entry| entry.inner.clone()).collect();
    bundle::bundle_list_dict(py, &bundle_list(user_id, &bundles))
}

#[pyfunction]
#[pyo3(signature = (one_time=None, one_time_id=None, one_time_kyber=None, one_time_kyber_id=None))]
pub fn prekey_claim_response<'py>(
    py: Python<'py>,
    one_time: Option<Vec<u8>>,
    one_time_id: Option<i64>,
    one_time_kyber: Option<Vec<u8>>,
    one_time_kyber_id: Option<i64>,
) -> PyResult<Bound<'py, PyDict>> {
    let classic = claimed(one_time.as_deref(), one_time_id);
    let quantum = claimed(one_time_kyber.as_deref(), one_time_kyber_id);
    bundle::claim_response_dict(py, &ClaimResponse::render(classic, quantum))
}

#[pyfunction]
pub fn prekey_status_unpublished(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    bundle::status_dict(py, &StatusReport::unpublished())
}

#[pyfunction]
#[pyo3(signature = (signed_prekey_id, available_opk_count, supports_v2=None))]
pub fn prekey_status_published(
    py: Python<'_>,
    signed_prekey_id: i64,
    available_opk_count: i64,
    supports_v2: Option<bool>,
) -> PyResult<Bound<'_, PyDict>> {
    bundle::status_dict(
        py,
        &StatusReport::published(signed_prekey_id, available_opk_count, supports_v2),
    )
}

#[pyfunction]
pub fn prekey_needs_replenishment(available_opk_count: i64) -> bool {
    StatusReport::needs_replenishment(available_opk_count)
}

#[pyfunction]
#[pyo3(signature = (header=None))]
pub fn prekey_client_device_id(header: Option<&str>) -> Option<String> {
    ClientDeviceId::parse(header?).map(|value| value.as_str().to_string())
}

#[pyfunction]
pub fn prekey_limits(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    limits::limits_dict(py)
}

fn claimed(public: Option<&[u8]>, key_id: Option<i64>) -> Option<(&[u8], i64)> {
    match (public, key_id) {
        (Some(bytes), Some(id)) => Some((bytes, id)),
        _ => None,
    }
}
