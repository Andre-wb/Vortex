use pyo3::prelude::*;
use vortex_proto::prekey::bundle::stored::StoredBundle;

#[pyclass(module = "vortex_chat", name = "StoredPreKeyBundle", frozen)]
pub struct PyStoredBundle {
    pub inner: StoredBundle,
}

#[pymethods]
impl PyStoredBundle {
    #[new]
    #[pyo3(signature = (
        identity_key,
        signed_prekey,
        signed_prekey_sig,
        signed_prekey_id,
        device_id=None,
        identity_key_ed=None,
        identity_key_sig=None,
        supports_v2=None,
        device_x3dh_pub=None,
        device_sign_pub=None,
        device_cert_sig=None,
        client_device_id=None,
        device_kyber_pub=None,
        device_kyber_sig=None,
        device_kyber_id=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        identity_key: Vec<u8>,
        signed_prekey: Vec<u8>,
        signed_prekey_sig: Vec<u8>,
        signed_prekey_id: i64,
        device_id: Option<i64>,
        identity_key_ed: Option<Vec<u8>>,
        identity_key_sig: Option<Vec<u8>>,
        supports_v2: Option<bool>,
        device_x3dh_pub: Option<Vec<u8>>,
        device_sign_pub: Option<Vec<u8>>,
        device_cert_sig: Option<Vec<u8>>,
        client_device_id: Option<String>,
        device_kyber_pub: Option<Vec<u8>>,
        device_kyber_sig: Option<Vec<u8>>,
        device_kyber_id: Option<i64>,
    ) -> Self {
        PyStoredBundle {
            inner: StoredBundle {
                device_id,
                identity_key,
                signed_prekey,
                signed_prekey_sig,
                signed_prekey_id,
                identity_key_ed,
                identity_key_sig,
                supports_v2,
                device_x3dh_pub,
                device_sign_pub,
                device_cert_sig,
                client_device_id,
                device_kyber_pub,
                device_kyber_sig,
                device_kyber_id,
            },
        }
    }

    #[getter]
    fn device_id(&self) -> Option<i64> {
        self.inner.device_id
    }

    #[getter]
    fn identity_key(&self) -> Vec<u8> {
        self.inner.identity_key.clone()
    }

    #[getter]
    fn signed_prekey(&self) -> Vec<u8> {
        self.inner.signed_prekey.clone()
    }

    #[getter]
    fn signed_prekey_sig(&self) -> Vec<u8> {
        self.inner.signed_prekey_sig.clone()
    }

    #[getter]
    fn signed_prekey_id(&self) -> i64 {
        self.inner.signed_prekey_id
    }

    #[getter]
    fn identity_key_ed(&self) -> Option<Vec<u8>> {
        self.inner.identity_key_ed.clone()
    }

    #[getter]
    fn identity_key_sig(&self) -> Option<Vec<u8>> {
        self.inner.identity_key_sig.clone()
    }

    #[getter]
    fn supports_v2(&self) -> Option<bool> {
        self.inner.supports_v2
    }

    #[getter]
    fn device_x3dh_pub(&self) -> Option<Vec<u8>> {
        self.inner.device_x3dh_pub.clone()
    }

    #[getter]
    fn device_sign_pub(&self) -> Option<Vec<u8>> {
        self.inner.device_sign_pub.clone()
    }

    #[getter]
    fn device_cert_sig(&self) -> Option<Vec<u8>> {
        self.inner.device_cert_sig.clone()
    }

    #[getter]
    fn client_device_id(&self) -> Option<String> {
        self.inner.client_device_id.clone()
    }

    #[getter]
    fn device_kyber_pub(&self) -> Option<Vec<u8>> {
        self.inner.device_kyber_pub.clone()
    }

    #[getter]
    fn device_kyber_sig(&self) -> Option<Vec<u8>> {
        self.inner.device_kyber_sig.clone()
    }

    #[getter]
    fn device_kyber_id(&self) -> Option<i64> {
        self.inner.device_kyber_id
    }

    fn __repr__(&self) -> String {
        match self.inner.device_id {
            Some(device_id) => format!("<StoredPreKeyBundle device_id={device_id}>"),
            None => "<StoredPreKeyBundle device_id=None>".to_string(),
        }
    }
}
