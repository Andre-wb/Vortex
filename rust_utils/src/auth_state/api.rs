use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_auth::challenge::id::ChallengeId;
use vortex_auth::challenge::secret::ChallengeSecret;
use vortex_auth::entry::address::ClientAddress;
use vortex_auth::error::StateError;
use vortex_auth::login::key::LoginPublicKey;
use vortex_auth::passkey::purpose::Purpose;
use vortex_auth::passkey::session::PasskeySession;
use vortex_auth::qr::session_id::QrSessionId;
use vortex_auth::token::jti::Jti;
use vortex_ratelimit::attempt::verdict::Verdict;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::auth_state::login::{PyLoginChallenge, PyLoginClaim};
use crate::auth_state::passkey::PyPasskeyClaim;
use crate::auth_state::qr::{PyQrAnswer, PyQrHandover, PyQrSession};
use crate::auth_state::shared;
use crate::auth_state::wallet::{PyWalletChallenge, PyWalletCheck};

fn unavailable(error: StateError) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

fn address(value: &str) -> PyResult<ClientAddress> {
    ClientAddress::parse(value).map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

fn judged(verdict: Verdict, what: &str) -> bool {
    if verdict == Verdict::Unavailable {
        log::warn!("общее состояние аутентификации недоступно — {what} отклонена");
    }
    verdict.allowed()
}

fn account(user_id: i64) -> PyResult<UserId> {
    UserId::of(user_id)
        .ok_or_else(|| PyValueError::new_err("номер учётной записи должен быть положительным"))
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
pub fn auth_connect_redis(
    py: Python<'_>,
    url: &str,
    pool_size: Option<usize>,
    key_prefix: Option<String>,
) -> PyResult<bool> {
    let mut config = RedisConfig::new(url);
    if let Some(size) = pool_size {
        config = config.pool_size(size);
    }
    if let Some(prefix) = key_prefix {
        config = config.key_prefix(prefix);
    }

    match py.allow_threads(|| shared::connect(config)) {
        Ok(()) => Ok(true),
        Err(BackboneError::Unconfigured) => Ok(false),
        Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
    }
}

#[pyfunction]
pub fn auth_state_mode() -> &'static str {
    shared::mode()
}

#[pyfunction]
pub fn auth_state_is_shared() -> bool {
    shared::is_shared()
}

#[pyfunction]
pub fn auth_revoke_access(py: Python<'_>, jti: &str, expires_at: f64) -> PyResult<bool> {
    let parsed = Jti::parse(jti).map_err(|refusal| PyValueError::new_err(refusal.to_string()))?;
    let service = shared::revocation();
    py.allow_threads(|| service.revoke(&parsed, expires_at))
        .map(|outcome| outcome.recorded())
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_access_revoked(py: Python<'_>, jti: &str) -> bool {
    match Jti::parse(jti) {
        Ok(parsed) => {
            let service = shared::revocation();
            py.allow_threads(|| service.is_revoked(&parsed))
        }
        Err(_) => true,
    }
}

#[pyfunction]
pub fn auth_arm_password_marker(py: Python<'_>, user_id: i64) -> PyResult<()> {
    let user = account(user_id)?;
    let service = shared::second_factor();
    py.allow_threads(|| service.arm(user)).map_err(unavailable)
}

#[pyfunction]
pub fn auth_password_marker_armed(py: Python<'_>, user_id: i64) -> bool {
    match UserId::of(user_id) {
        Some(user) => {
            let service = shared::second_factor();
            py.allow_threads(|| service.armed(user))
        }
        None => false,
    }
}

#[pyfunction]
pub fn auth_handoff_seen(py: Python<'_>, jti: &str) -> PyResult<bool> {
    let parsed = Jti::parse(jti).map_err(|refusal| PyValueError::new_err(refusal.to_string()))?;
    let service = shared::replay();
    py.allow_threads(|| service.seen(&parsed))
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_handoff_accept(py: Python<'_>, jti: &str) -> PyResult<bool> {
    let parsed = Jti::parse(jti).map_err(|refusal| PyValueError::new_err(refusal.to_string()))?;
    let service = shared::replay();
    py.allow_threads(|| service.accept(&parsed))
        .map(|outcome| outcome.accepted())
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_handoff_forget_all() -> bool {
    shared::forget_replay_in_memory()
}

#[pyfunction]
pub fn auth_handoff_token_seconds() -> u64 {
    vortex_auth::handoff::lifetime::TOKEN_SECONDS
}

#[pyfunction]
pub fn auth_wallet_issue(py: Python<'_>, user_id: i64) -> PyResult<PyWalletChallenge> {
    let user = account(user_id)?;
    let service = shared::wallet_link();
    py.allow_threads(|| service.issue(user))
        .map(PyWalletChallenge::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_wallet_check(py: Python<'_>, user_id: i64, supplied: &str) -> PyResult<PyWalletCheck> {
    let user = account(user_id)?;
    let service = shared::wallet_link();
    py.allow_threads(|| service.check(user, supplied))
        .map(PyWalletCheck::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_wallet_burn(py: Python<'_>, user_id: i64) -> PyResult<()> {
    let user = account(user_id)?;
    let service = shared::wallet_link();
    py.allow_threads(|| service.burn(user)).map_err(unavailable)
}

fn secret(challenge: &[u8]) -> PyResult<ChallengeSecret> {
    ChallengeSecret::of(challenge.to_vec())
        .map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

fn passkey_session(session_id: &str) -> PyResult<PasskeySession> {
    PasskeySession::parse(session_id).map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

#[pyfunction]
pub fn auth_passkey_open_registration(
    py: Python<'_>,
    challenge: &[u8],
    user_id: i64,
) -> PyResult<String> {
    let user = account(user_id)?;
    let drawn = secret(challenge)?;
    let service = shared::passkey();
    py.allow_threads(|| service.open(drawn, Purpose::Registration(user)))
        .map(|session| session.as_str().to_owned())
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_passkey_open_login(py: Python<'_>, challenge: &[u8]) -> PyResult<String> {
    let drawn = secret(challenge)?;
    let service = shared::passkey();
    py.allow_threads(|| service.open(drawn, Purpose::Login))
        .map(|session| session.as_str().to_owned())
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_passkey_claim_registration(
    py: Python<'_>,
    session_id: &str,
    user_id: i64,
) -> PyResult<PyPasskeyClaim> {
    let user = account(user_id)?;
    let session = passkey_session(session_id)?;
    let service = shared::passkey();
    py.allow_threads(|| service.claim_registration(&session, user))
        .map(PyPasskeyClaim::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_passkey_claim_login(py: Python<'_>, session_id: &str) -> PyResult<PyPasskeyClaim> {
    let session = passkey_session(session_id)?;
    let service = shared::passkey();
    py.allow_threads(|| service.claim_login(&session))
        .map(PyPasskeyClaim::of)
        .map_err(unavailable)
}

fn qr_session(session_id: &str) -> PyResult<QrSessionId> {
    QrSessionId::parse(session_id).map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

#[pyfunction]
pub fn auth_login_issue(py: Python<'_>, user_id: i64, pubkey: &str) -> PyResult<PyLoginChallenge> {
    let user = account(user_id)?;
    let key = LoginPublicKey::parse(pubkey)
        .map_err(|refusal| PyValueError::new_err(refusal.to_string()))?;
    let service = shared::login_challenges();
    py.allow_threads(|| service.issue_for_account(user, key))
        .map(PyLoginChallenge::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_login_issue_decoy(py: Python<'_>) -> PyResult<PyLoginChallenge> {
    let service = shared::login_challenges();
    py.allow_threads(|| service.issue_decoy())
        .map(PyLoginChallenge::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_login_claim(
    py: Python<'_>,
    challenge_id: &str,
    pubkey: &str,
) -> PyResult<PyLoginClaim> {
    let id = ChallengeId::parse(challenge_id)
        .map_err(|refusal| PyValueError::new_err(refusal.to_string()))?;
    let service = shared::login_challenges();
    py.allow_threads(|| service.claim_for_account(&id, pubkey))
        .map(PyLoginClaim::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_qr_open(py: Python<'_>) -> PyResult<PyQrSession> {
    let service = shared::qr_login();
    py.allow_threads(|| service.open())
        .map(PyQrSession::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_qr_answer(py: Python<'_>, session_id: &str) -> PyResult<PyQrAnswer> {
    let session = qr_session(session_id)?;
    let service = shared::qr_login();
    py.allow_threads(|| service.answer(&session))
        .map(PyQrAnswer::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_qr_confirm(py: Python<'_>, session_id: &str, user_id: i64) -> PyResult<&'static str> {
    let session = qr_session(session_id)?;
    let user = account(user_id)?;
    let service = shared::qr_login();
    py.allow_threads(|| service.confirm(&session, user))
        .map(|confirmation| confirmation.outcome())
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_qr_hand_over(py: Python<'_>, session_id: &str) -> PyResult<PyQrHandover> {
    let session = qr_session(session_id)?;
    let service = shared::qr_login();
    py.allow_threads(|| service.hand_over(&session))
        .map(PyQrHandover::of)
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_burn_password_marker(py: Python<'_>, user_id: i64) -> PyResult<()> {
    let user = account(user_id)?;
    let service = shared::second_factor();
    py.allow_threads(|| service.disarm(user))
        .map_err(unavailable)
}

#[pyfunction]
pub fn auth_entry_login_allowed(py: Python<'_>, client: &str) -> PyResult<bool> {
    let client = address(client)?;
    let service = shared::entry_rate();
    let verdict = py.allow_threads(|| service.allow_login(&client));
    Ok(judged(verdict, "попытка входа"))
}

#[pyfunction]
pub fn auth_entry_register_allowed(py: Python<'_>, client: &str) -> PyResult<bool> {
    let client = address(client)?;
    let service = shared::entry_rate();
    let verdict = py.allow_threads(|| service.allow_registration(&client));
    Ok(judged(verdict, "попытка регистрации"))
}

#[pyfunction]
pub fn auth_totp_attempt_allowed(py: Python<'_>, user_id: i64) -> PyResult<bool> {
    let user = account(user_id)?;
    let service = shared::totp_rate();
    let verdict = py.allow_threads(|| service.allow(user));
    Ok(judged(verdict, "попытка второго фактора"))
}
