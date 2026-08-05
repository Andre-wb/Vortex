//! Адрес источника запроса.
//!
//! Хранится строкой, а не `IpAddr`: прежний Python-код допускал значения вида
//! `"unknown"` и `"localhost"`, и списки доступа опираются на это.

use serde::Serialize;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ClientIp(String);

impl ClientIp {
    pub fn new(value: impl Into<String>) -> Self {
        ClientIp(value.into())
    }

    /// Значение-заглушка, когда адрес источника определить не удалось.
    pub fn unknown() -> Self {
        ClientIp("unknown".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Разбор в `IpAddr`; `None` для нечисловых значений вроде `localhost`.
    pub fn parsed(&self) -> Option<IpAddr> {
        self.0.parse().ok()
    }

    pub fn is_valid_ip(&self) -> bool {
        self.parsed().is_some()
    }
}

impl fmt::Display for ClientIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ClientIp {
    fn from(value: &str) -> Self {
        ClientIp(value.to_owned())
    }
}

impl From<String> for ClientIp {
    fn from(value: String) -> Self {
        ClientIp(value)
    }
}

#[cfg(test)]
mod tests {
    use super::ClientIp;

    #[test]
    fn distinguishes_numeric_addresses() {
        assert!(ClientIp::from("10.0.0.1").is_valid_ip());
        assert!(!ClientIp::from("localhost").is_valid_ip());
        assert!(!ClientIp::unknown().is_valid_ip());
    }
}
