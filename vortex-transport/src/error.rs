use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    ShortIdNotHex(String),
    ShortIdLength { expected: usize, got: usize },
    KeyLength { expected: usize, got: usize },
    Seal(String),
    TrojanUnconfigured,
    TrojanAddress(String),
    ShadowsocksUnconfigured,
    ShadowsocksAddress(String),
    ShadowsocksPadding { max: usize, got: usize },
    ShadowsocksRequestTooLong,
    NaiveCredential(String),
    NaiveProbeDomain(String),
    NaiveUpstream(String),
    NaiveEmail(String),
    NaiveHost(String),
    NaivePort,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::ShortIdNotHex(value) => {
                write!(f, "short_id не шестнадцатеричный: {value}")
            }
            TransportError::ShortIdLength { expected, got } => write!(
                f,
                "short_id должен быть длиной {expected} байт, получено {got}"
            ),
            TransportError::KeyLength { expected, got } => {
                write!(f, "ключ должен быть длиной {expected} байт, получено {got}")
            }
            TransportError::Seal(msg) => write!(f, "не удалось запечатать конверт: {msg}"),
            TransportError::TrojanUnconfigured => {
                write!(f, "пароль Trojan не задан: запрос собрать нечем")
            }
            TransportError::TrojanAddress(host) => {
                write!(f, "адрес назначения Trojan непредставим: {host}")
            }
            TransportError::ShadowsocksUnconfigured => {
                write!(f, "пароль Shadowsocks не задан: запрос собрать нечем")
            }
            TransportError::ShadowsocksAddress(host) => {
                write!(f, "адрес назначения Shadowsocks непредставим: {host}")
            }
            TransportError::ShadowsocksPadding { max, got } => write!(
                f,
                "паддинг запроса Shadowsocks не длиннее {max} байт, получено {got}"
            ),
            TransportError::ShadowsocksRequestTooLong => {
                write!(f, "заголовок запроса Shadowsocks не помещается в кадр")
            }
            TransportError::NaiveCredential(field) => {
                write!(f, "значение NaiveProxy непредставимо в Caddyfile: {field}")
            }
            TransportError::NaiveProbeDomain(domain) => {
                write!(f, "probe-домен NaiveProxy не похож на имя хоста: {domain}")
            }
            TransportError::NaiveUpstream(url) => {
                write!(f, "адрес backend-а NaiveProxy непредставим: {url}")
            }
            TransportError::NaiveEmail(email) => {
                write!(f, "почта для ACME непредставима: {email}")
            }
            TransportError::NaiveHost(host) => {
                write!(f, "адрес сервера NaiveProxy непредставим: {host}")
            }
            TransportError::NaivePort => write!(f, "порт NaiveProxy не задан"),
        }
    }
}

impl std::error::Error for TransportError {}

pub type Result<T> = std::result::Result<T, TransportError>;
