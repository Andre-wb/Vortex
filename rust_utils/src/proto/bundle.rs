use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use vortex_proto::prekey::bundle::device_bundle::DeviceBundle;
use vortex_proto::prekey::bundle::list::BundleList;
use vortex_proto::prekey::bundle::response::BundleResponse;
use vortex_proto::prekey::claim::response::ClaimResponse;
use vortex_proto::prekey::status::report::StatusReport;

pub fn device_bundle_dict<'py>(
    py: Python<'py>,
    bundle: &DeviceBundle,
) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("device_id", bundle.device_id)?;
    out.set_item("identity_key", &bundle.identity_key)?;
    out.set_item("signed_prekey", &bundle.signed_prekey)?;
    out.set_item("signed_prekey_sig", &bundle.signed_prekey_sig)?;
    out.set_item("signed_prekey_id", bundle.signed_prekey_id)?;
    out.set_item("identity_key_ed", &bundle.identity_key_ed)?;
    out.set_item("identity_key_sig", &bundle.identity_key_sig)?;
    out.set_item("supports_v2", bundle.supports_v2)?;
    out.set_item("device_x3dh_pub", &bundle.device_x3dh_pub)?;
    out.set_item("device_sign_pub", &bundle.device_sign_pub)?;
    out.set_item("device_cert_sig", &bundle.device_cert_sig)?;
    out.set_item("client_device_id", &bundle.client_device_id)?;
    out.set_item("device_kyber_pub", &bundle.device_kyber_pub)?;
    out.set_item("device_kyber_sig", &bundle.device_kyber_sig)?;
    out.set_item("device_kyber_id", bundle.device_kyber_id)?;
    out.set_item("one_time_prekey", &bundle.one_time_prekey)?;
    out.set_item("one_time_prekey_id", bundle.one_time_prekey_id)?;
    Ok(out)
}

pub fn bundle_response_dict<'py>(
    py: Python<'py>,
    response: &BundleResponse,
) -> PyResult<Bound<'py, PyDict>> {
    let out = device_bundle_dict(py, &response.bundle)?;
    out.set_item("user_id", response.user_id)?;
    Ok(out)
}

pub fn bundle_list_dict<'py>(py: Python<'py>, list: &BundleList) -> PyResult<Bound<'py, PyDict>> {
    let bundles = PyList::empty(py);
    for bundle in &list.bundles {
        bundles.append(device_bundle_dict(py, bundle)?)?;
    }
    let out = PyDict::new(py);
    out.set_item("user_id", list.user_id)?;
    out.set_item("bundles", bundles)?;
    Ok(out)
}

pub fn claim_response_dict<'py>(
    py: Python<'py>,
    response: &ClaimResponse,
) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("one_time_prekey", &response.one_time_prekey)?;
    out.set_item("one_time_prekey_id", response.one_time_prekey_id)?;
    out.set_item("one_time_kyber_prekey", &response.one_time_kyber_prekey)?;
    out.set_item(
        "one_time_kyber_prekey_id",
        response.one_time_kyber_prekey_id,
    )?;
    Ok(out)
}

pub fn status_dict<'py>(py: Python<'py>, report: &StatusReport) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("published", report.published)?;
    out.set_item("signed_prekey_id", report.signed_prekey_id)?;
    out.set_item("available_opk_count", report.available_opk_count)?;
    out.set_item("low_opk_warning", report.low_opk_warning)?;
    out.set_item("supports_v2", report.supports_v2)?;
    Ok(out)
}
