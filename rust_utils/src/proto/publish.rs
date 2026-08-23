use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vortex_proto::prekey::publish::parsed::ParsedPublish;

use crate::proto::rejection::PyProtoRejection;

#[pyclass(module = "vortex_chat", name = "PreKeyPublish", frozen)]
pub struct PyPreKeyPublish {
    #[pyo3(get)]
    pub rejection: Option<PyProtoRejection>,
    parsed: Option<ParsedPublish>,
}

impl PyPreKeyPublish {
    pub fn refused(rejection: PyProtoRejection) -> Self {
        PyPreKeyPublish {
            rejection: Some(rejection),
            parsed: None,
        }
    }

    pub fn accepted(parsed: ParsedPublish) -> Self {
        PyPreKeyPublish {
            rejection: None,
            parsed: Some(parsed),
        }
    }
}

#[pymethods]
impl PyPreKeyPublish {
    #[getter]
    fn identity_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        match &self.parsed {
            Some(parsed) => PyBytes::new(py, parsed.account.identity_key.as_bytes()),
            None => PyBytes::new(py, &[]),
        }
    }

    #[getter]
    fn signed_prekey<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        match &self.parsed {
            Some(parsed) => PyBytes::new(py, parsed.account.signed_prekey.as_bytes()),
            None => PyBytes::new(py, &[]),
        }
    }

    #[getter]
    fn signed_prekey_sig<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        match &self.parsed {
            Some(parsed) => PyBytes::new(py, parsed.account.signed_prekey_sig.as_bytes()),
            None => PyBytes::new(py, &[]),
        }
    }

    #[getter]
    fn signed_prekey_id(&self) -> i64 {
        self.parsed
            .as_ref()
            .map_or(0, |parsed| parsed.account.signed_prekey_id)
    }

    #[getter]
    fn identity_key_ed<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let parsed = self.parsed.as_ref()?;
        parsed
            .account
            .identity_key_ed
            .as_ref()
            .map(|key| PyBytes::new(py, key.as_bytes()))
    }

    #[getter]
    fn identity_key_sig<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let parsed = self.parsed.as_ref()?;
        parsed
            .account
            .identity_key_sig
            .as_ref()
            .map(|signature| PyBytes::new(py, signature.as_bytes()))
    }

    #[getter]
    fn supports_v2(&self) -> Option<bool> {
        self.parsed.as_ref().and_then(|parsed| parsed.supports_v2)
    }

    #[getter]
    fn device_x3dh_pub<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let parsed = self.parsed.as_ref()?;
        parsed
            .device
            .x3dh_pub
            .as_ref()
            .map(|key| PyBytes::new(py, key.as_bytes()))
    }

    #[getter]
    fn device_sign_pub<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let parsed = self.parsed.as_ref()?;
        parsed
            .device
            .sign_pub
            .as_ref()
            .map(|key| PyBytes::new(py, key.as_bytes()))
    }

    #[getter]
    fn device_cert_sig<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let parsed = self.parsed.as_ref()?;
        parsed
            .device
            .cert_sig
            .as_ref()
            .map(|signature| PyBytes::new(py, signature.as_bytes()))
    }

    #[getter]
    fn device_kyber_pub<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let parsed = self.parsed.as_ref()?;
        parsed
            .kyber
            .public
            .as_ref()
            .map(|key| PyBytes::new(py, key.as_bytes().as_slice()))
    }

    #[getter]
    fn device_kyber_sig<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let parsed = self.parsed.as_ref()?;
        parsed
            .kyber
            .signature
            .as_ref()
            .map(|signature| PyBytes::new(py, signature.as_bytes()))
    }

    #[getter]
    fn device_kyber_id(&self) -> Option<i64> {
        self.parsed.as_ref().and_then(|parsed| parsed.kyber.id)
    }

    #[getter]
    fn one_time<'py>(&self, py: Python<'py>) -> Vec<(i64, Bound<'py, PyBytes>)> {
        match &self.parsed {
            Some(parsed) => parsed
                .one_time
                .iter()
                .map(|key| (key.key_id, PyBytes::new(py, key.public.as_bytes())))
                .collect(),
            None => Vec::new(),
        }
    }

    #[getter]
    fn one_time_kyber<'py>(&self, py: Python<'py>) -> Vec<(i64, Bound<'py, PyBytes>)> {
        match &self.parsed {
            Some(parsed) => parsed
                .one_time_kyber
                .iter()
                .map(|key| {
                    (
                        key.key_id,
                        PyBytes::new(py, key.public.as_bytes().as_slice()),
                    )
                })
                .collect(),
            None => Vec::new(),
        }
    }

    #[getter]
    fn complaints(&self) -> Vec<&'static str> {
        match &self.parsed {
            Some(parsed) => parsed
                .complaints
                .iter()
                .map(|complaint| complaint.detail())
                .collect(),
            None => Vec::new(),
        }
    }

    fn __repr__(&self) -> String {
        match &self.rejection {
            Some(rejection) => format!("<PreKeyPublish refused status={}>", rejection.status),
            None => "<PreKeyPublish accepted>".to_string(),
        }
    }
}
