//! Настройки транспортного слоя.

/// Предел размера тела, после которого запрос отклоняется кодом 413 ещё до
/// буферизации в память.
pub const DEFAULT_MAX_BODY_BYTES: usize = 25 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub max_body_bytes: usize,
    /// Сети доверенных прокси в формате CIDR или отдельных адресов.
    pub trusted_proxies: Vec<String>,
}

impl Default for GuardConfig {
    fn default() -> Self {
        GuardConfig {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            // Пустой список: заголовкам X-Forwarded-For по умолчанию не верим.
            trusted_proxies: Vec::new(),
        }
    }
}

impl GuardConfig {
    pub fn new() -> Self {
        GuardConfig::default()
    }

    pub fn max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }

    pub fn trusted_proxies<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trusted_proxies = entries.into_iter().map(Into::into).collect();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::GuardConfig;

    #[test]
    fn trusts_no_proxy_by_default() {
        assert!(GuardConfig::default().trusted_proxies.is_empty());
        assert_eq!(GuardConfig::default().max_body_bytes, 25 * 1024 * 1024);
    }
}
