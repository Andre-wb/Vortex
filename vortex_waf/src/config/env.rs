//! Чтение настроек из окружения.
//!
//! Единственное место крейта, обращающееся к `std::env` — остальной код
//! получает готовую конфигурацию и остаётся пригодным для тестов.

use crate::config::guard_config::{GuardConfig, DEFAULT_MAX_BODY_BYTES};
use std::env;

pub const ENV_TRUSTED_PROXIES: &str = "TRUSTED_PROXY_IPS";
pub const ENV_MAX_BODY_BYTES: &str = "WAF_MAX_BODY_BYTES";
pub const ENV_CSRF_SECRET: &str = "CSRF_SECRET";
pub const ENV_JWT_SECRET: &str = "JWT_SECRET";

/// Конфигурация транспортного слоя из переменных окружения.
pub fn guard_config_from_env() -> GuardConfig {
    GuardConfig {
        max_body_bytes: env::var(ENV_MAX_BODY_BYTES)
            .ok()
            .and_then(|raw| raw.trim().parse().ok())
            .unwrap_or(DEFAULT_MAX_BODY_BYTES),
        trusted_proxies: split_list(&env::var(ENV_TRUSTED_PROXIES).unwrap_or_default()),
    }
}

/// Секрет для подписи капчи: `CSRF_SECRET`, иначе `JWT_SECRET`, иначе пусто.
pub fn captcha_secret_from_env() -> String {
    for key in [ENV_CSRF_SECRET, ENV_JWT_SECRET] {
        if let Ok(value) = env::var(key) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    String::new()
}

/// Разбор списка через запятую с отбрасыванием пустых элементов.
pub fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::split_list;

    #[test]
    fn splits_and_trims() {
        assert_eq!(
            split_list(" 10.0.0.5 , 192.168.1.0/24 ,, "),
            vec!["10.0.0.5", "192.168.1.0/24"]
        );
        assert!(split_list("").is_empty());
    }
}
