use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackboneError {
    Unconfigured,
    Connect(String),
    Command(String),
    Degraded,
}

impl fmt::Display for BackboneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackboneError::Unconfigured => write!(f, "Redis не настроен"),
            BackboneError::Connect(reason) => {
                write!(f, "не удалось подключиться к Redis: {reason}")
            }
            BackboneError::Command(reason) => write!(f, "команда Redis не выполнена: {reason}"),
            BackboneError::Degraded => write!(f, "Redis помечен недоступным, идёт восстановление"),
        }
    }
}

impl std::error::Error for BackboneError {}

pub type Result<T> = std::result::Result<T, BackboneError>;
