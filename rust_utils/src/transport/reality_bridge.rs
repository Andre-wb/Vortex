use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::Arc;
use vortex_transport::ports::clock::Clock;
use vortex_transport::ports::random_source::RandomSource;
use vortex_transport::random::os_random::OsRandom;
use vortex_transport::reality::auth::envelope::{Envelope, ENVELOPE_VERSION};
use vortex_transport::reality::auth::salt::{Salt, SALT_LEN};
use vortex_transport::reality::auth::sealed_auth::{SealedAuth, SESSION_ID_LEN, X25519_KEY_LEN};
use vortex_transport::reality::auth::sealer;
use vortex_transport::reality::authenticator::RealityAuthenticator;
use vortex_transport::reality::builder::AuthenticatorBuilder;
use vortex_transport::reality::config::{
    RealityConfig, DEFAULT_AUTH_WINDOW_FUTURE_SECS, DEFAULT_AUTH_WINDOW_PAST_SECS,
};
use vortex_transport::reality::handshake::client_hello;
use vortex_transport::reality::short_id::generator;
use vortex_transport::reality::short_id::value::{ShortId, SHORT_ID_HEX_LEN};
use vortex_transport::time::system_clock::SystemClock;
use x25519_dalek::StaticSecret;

#[pyclass(module = "vortex_chat", name = "RealityAuth")]
pub struct PyRealityAuth {
    authenticator: RealityAuthenticator,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

#[pymethods]
impl PyRealityAuth {
    #[new]
    #[pyo3(signature = (
        private_key=None,
        auth_window_past=DEFAULT_AUTH_WINDOW_PAST_SECS,
        auth_window_future=DEFAULT_AUTH_WINDOW_FUTURE_SECS,
    ))]
    fn new(
        private_key: Option<&[u8]>,
        auth_window_past: i64,
        auth_window_future: i64,
    ) -> PyResult<Self> {
        let random: Arc<dyn RandomSource> = Arc::new(OsRandom::new());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let mut builder = AuthenticatorBuilder::new()
            .with_random(random.clone())
            .with_clock(clock.clone())
            .with_config(
                RealityConfig::new()
                    .auth_window_past_secs(auth_window_past)
                    .auth_window_future_secs(auth_window_future),
            );

        if let Some(bytes) = private_key {
            builder = builder.with_secret(StaticSecret::from(to_key(bytes)?));
        }

        Ok(PyRealityAuth {
            authenticator: builder.build(),
            random,
            clock,
        })
    }

    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.authenticator.public_key())
    }

    fn add_short_id(&self, short_id: &str) -> PyResult<bool> {
        Ok(self
            .authenticator
            .short_ids()
            .insert(parse_short_id(short_id)?))
    }

    fn remove_short_id(&self, short_id: &str) -> PyResult<bool> {
        Ok(self
            .authenticator
            .short_ids()
            .remove(&parse_short_id(short_id)?))
    }

    fn generate_short_id(&self) -> String {
        let short_id = generator::generate(self.random.as_ref());
        let hex = short_id.to_hex();
        self.authenticator.short_ids().insert(short_id);
        hex
    }

    fn short_ids(&self) -> Vec<String> {
        self.authenticator
            .short_ids()
            .all()
            .iter()
            .map(ShortId::to_hex)
            .collect()
    }

    fn authorized_count(&self) -> usize {
        self.authenticator.short_ids().len()
    }

    #[pyo3(signature = (short_id, server_public, timestamp=None))]
    fn build_client_hello_auth<'py>(
        &self,
        py: Python<'py>,
        short_id: &str,
        server_public: &[u8],
        timestamp: Option<i64>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let seconds = timestamp.unwrap_or_else(|| self.clock.unix_seconds());
        let envelope = envelope(short_id, seconds)?;
        let sealed = sealer::seal(server_public, &envelope, self.random.as_ref())
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        Ok(sealed_to_py(py, sealed))
    }

    #[pyo3(signature = (short_id, server_public, timestamp, ephemeral_secret, salt))]
    fn build_client_hello_auth_derand<'py>(
        &self,
        py: Python<'py>,
        short_id: &str,
        server_public: &[u8],
        timestamp: i64,
        ephemeral_secret: &[u8],
        salt: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let sealed = sealer::seal_with_ephemeral(
            server_public,
            &envelope(short_id, timestamp)?,
            to_key(ephemeral_secret)?,
            to_salt(salt)?,
        )
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
        Ok(sealed_to_py(py, sealed))
    }

    fn verify_client_hello_auth(
        &self,
        ephemeral_public: &[u8],
        session_id: &[u8],
    ) -> (bool, String) {
        report(self.authenticator.verify(ephemeral_public, session_id))
    }

    fn is_reality_client(&self, client_hello: &[u8]) -> (bool, String) {
        report(self.authenticator.authenticate(client_hello))
    }

    #[staticmethod]
    fn parse_client_hello<'py>(
        py: Python<'py>,
        data: &[u8],
    ) -> Option<(Bound<'py, PyBytes>, Option<Bound<'py, PyBytes>>)> {
        client_hello::parse(data).map(|hello| {
            (
                PyBytes::new(py, &hello.session_id),
                hello.key_share.map(|key| PyBytes::new(py, &key)),
            )
        })
    }

    #[getter]
    fn auth_window_past(&self) -> i64 {
        self.authenticator.config().auth_window_past_secs
    }

    #[getter]
    fn auth_window_future(&self) -> i64 {
        self.authenticator.config().auth_window_future_secs
    }

    #[getter]
    fn envelope_version(&self) -> u8 {
        ENVELOPE_VERSION
    }

    #[getter]
    fn session_id_len(&self) -> usize {
        SESSION_ID_LEN
    }

    #[getter]
    fn salt_len(&self) -> usize {
        SALT_LEN
    }

    #[getter]
    fn short_id_hex_len(&self) -> usize {
        SHORT_ID_HEX_LEN
    }
}

fn envelope(short_id: &str, timestamp: i64) -> PyResult<Envelope> {
    let seconds = u32::try_from(timestamp).map_err(|_| {
        PyValueError::new_err(format!(
            "время конверта должно укладываться в 0..={}, получено {timestamp}",
            u32::MAX
        ))
    })?;
    Envelope::current(seconds, parse_short_id(short_id)?)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

fn sealed_to_py(py: Python<'_>, sealed: SealedAuth) -> (Bound<'_, PyBytes>, Bound<'_, PyBytes>) {
    (
        PyBytes::new(py, &sealed.ephemeral_public),
        PyBytes::new(py, &sealed.session_id),
    )
}

fn report(verdict: vortex_transport::reality::verdict::AuthVerdict) -> (bool, String) {
    match verdict.short_id() {
        Some(short_id) => (true, short_id.to_hex()),
        None => (false, String::new()),
    }
}

fn parse_short_id(value: &str) -> PyResult<ShortId> {
    ShortId::canonical(value).map_err(|err| PyValueError::new_err(err.to_string()))
}

fn to_key(bytes: &[u8]) -> PyResult<[u8; X25519_KEY_LEN]> {
    bytes.try_into().map_err(|_| {
        PyValueError::new_err(format!(
            "ключ должен быть длиной {X25519_KEY_LEN} байт, получено {}",
            bytes.len()
        ))
    })
}

fn to_salt(bytes: &[u8]) -> PyResult<Salt> {
    bytes.try_into().map_err(|_| {
        PyValueError::new_err(format!(
            "соль должна быть длиной {SALT_LEN} байт, получено {}",
            bytes.len()
        ))
    })
}
