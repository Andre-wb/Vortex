use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    ShortIdNotHex(String),
    ShortIdLength { expected: usize, got: usize },
    KeyLength { expected: usize, got: usize },
    Seal(String),
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
        }
    }
}

impl std::error::Error for TransportError {}

pub type Result<T> = std::result::Result<T, TransportError>;
