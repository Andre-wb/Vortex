use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use vortex_ratelimit::antispam::outcome::SpamOutcome;
use vortex_ratelimit::attempt::member::Member;
use vortex_ratelimit::attempt::membership::Membership;
use vortex_ratelimit::attempt::verdict::Verdict;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::ratelimit::shared;

fn member(value: &str, what: &str) -> Option<Member> {
    match Member::parse(value) {
        Ok(parsed) => Some(parsed),
        Err(refusal) => {
            log::warn!("{what} нельзя сосчитать: {refusal}");
            None
        }
    }
}

fn judged(verdict: Verdict, what: &str) -> bool {
    if verdict == Verdict::Unavailable {
        log::warn!("общий счёт обращений недоступен — {what} отклонено");
    }
    verdict.allowed()
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
pub fn ratelimit_connect_redis(
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
pub fn ratelimit_mode() -> &'static str {
    shared::mode()
}

#[pyfunction]
pub fn ratelimit_is_shared() -> bool {
    shared::is_shared()
}

#[pyfunction]
pub fn ratelimit_secrets_address_allowed(py: Python<'_>, address: &str, limit: u32) -> bool {
    let what = "обращение за транспортными паролями с адреса";
    let Some(client) = member(address, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.secrets.allow_address(&client, limit, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_secrets_account_allowed(py: Python<'_>, user_id: i64, limit: u32) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.secrets.allow_account(user_id, limit, shared::now()));
    judged(
        verdict,
        "обращение за транспортными паролями учётной записи",
    )
}

#[pyfunction]
pub fn ratelimit_gossip_allowed(py: Python<'_>, address: &str) -> bool {
    let what = "пакет сплетен";
    let Some(peer) = member(address, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.gossip.allow(&peer, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_vault_read_allowed(py: Python<'_>, user_id: i64) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.vault.allow(user_id, shared::now()));
    judged(verdict, "чтение профиль-хранилища")
}

#[pyfunction]
pub fn ratelimit_notification_sender_allowed(py: Python<'_>, user_id: i64) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.notification.allow_from(user_id, shared::now()));
    judged(verdict, "уведомление от отправителя")
}

#[pyfunction]
pub fn ratelimit_notification_pair_allowed(
    py: Python<'_>,
    user_id: i64,
    recipient_id: i64,
) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| {
        limits
            .notification
            .allow_to(user_id, recipient_id, shared::now())
    });
    judged(verdict, "уведомление этому получателю")
}

#[pyfunction]
pub fn ratelimit_translation_allowed(py: Python<'_>, user_id: i64) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.translation.allow(user_id, shared::now()));
    judged(verdict, "перевод сообщения")
}

#[pyfunction]
pub fn ratelimit_preview_account_allowed(py: Python<'_>, user_id: i64) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.preview.allow_account(user_id, shared::now()));
    judged(verdict, "предпросмотр ссылки учётной записью")
}

#[pyfunction]
pub fn ratelimit_preview_address_allowed(py: Python<'_>, address: &str) -> bool {
    let what = "предпросмотр ссылки с адреса";
    let Some(client) = member(address, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.preview.allow_address(&client, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_assistant_allowed(py: Python<'_>, user_id: i64) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.assistant.allow(user_id, shared::now()));
    judged(verdict, "обращение к помощнику")
}

#[pyfunction]
pub fn ratelimit_replication_allowed(py: Python<'_>, address: &str) -> bool {
    let what = "конверт репликации";
    let Some(origin) = member(address, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.replication.allow(&origin, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_node_allowed(py: Python<'_>, node: &str) -> bool {
    let what = "обращение узла федерации";
    let Some(peer) = member(node, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.node.allow(&peer, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_push_register_allowed(py: Python<'_>, address: &str) -> bool {
    let what = "регистрация push-токена";
    let Some(client) = member(address, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.push.allow_registration(&client, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_push_wake_allowed(py: Python<'_>, address: &str) -> bool {
    let what = "пробуждение подписчиков";
    let Some(client) = member(address, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.push.allow_wake(&client, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_pseudonym_resolve_allowed(
    py: Python<'_>,
    limit: u32,
    window_seconds: u64,
) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.pseudonym.allow(limit, window_seconds, shared::now()));
    judged(verdict, "раскрытие псевдонима")
}

#[pyfunction]
pub fn ratelimit_flood_check(
    py: Python<'_>,
    room_id: i64,
    user_id: i64,
    threshold: i64,
) -> (bool, u32, bool) {
    let membership = Membership::of(room_id, user_id);
    let limits = shared::limits();
    let outcome = py.allow_threads(|| limits.flood.judge(membership, threshold, shared::now()));
    (outcome.flooding(), outcome.strikes(), outcome.earns_a_ban())
}

#[pyfunction]
pub fn ratelimit_flood_forget(py: Python<'_>, room_id: i64, user_id: i64) {
    let membership = Membership::of(room_id, user_id);
    let limits = shared::limits();
    py.allow_threads(|| limits.flood.forget_window(membership));
}

#[pyfunction]
pub fn ratelimit_guest_login_allowed(py: Python<'_>, address: &str) -> bool {
    let what = "гостевой вход с адреса";
    let Some(client) = member(address, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.guest.allow(&client, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_shard_store_allowed(py: Python<'_>, address: &str) -> bool {
    let what = "сохранение доли ключа с адреса";
    let Some(client) = member(address, what) else {
        return false;
    };
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.shard.allow(&client, shared::now()));
    judged(verdict, what)
}

#[pyfunction]
pub fn ratelimit_signal_allowed(py: Python<'_>, user_id: i64) -> bool {
    let limits = shared::limits();
    let verdict = py.allow_threads(|| limits.signal.allow(user_id, shared::now()));
    judged(verdict, "сигнальное сообщение")
}

#[pyfunction]
pub fn ratelimit_repeat_spam(
    py: Python<'_>,
    room_id: i64,
    user_id: i64,
    text: &str,
) -> (bool, &'static str) {
    let membership = Membership::of(room_id, user_id);
    let limits = shared::limits();
    let outcome = py.allow_threads(|| limits.repeats.judge(membership, text, shared::now()));
    if outcome == SpamOutcome::Unavailable {
        log::warn!("счёт повторов недоступен — сообщение задержано");
    }
    (outcome.blocks(), outcome.reason())
}

#[pyfunction]
pub fn ratelimit_link_spam(py: Python<'_>, room_id: i64, user_id: i64) -> (bool, &'static str) {
    let membership = Membership::of(room_id, user_id);
    let limits = shared::limits();
    let outcome = py.allow_threads(|| limits.links.judge(membership, shared::now()));
    if outcome == SpamOutcome::Unavailable {
        log::warn!("счёт ссылок недоступен — сообщение задержано");
    }
    (outcome.blocks(), outcome.reason())
}
