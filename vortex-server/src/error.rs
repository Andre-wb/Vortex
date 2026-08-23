use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerError {
    Upstream(String),
    Metrics(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::Upstream(reason) => {
                write!(f, "запрос к Python не выполнен: {reason}")
            }
            ServerError::Metrics(reason) => {
                write!(f, "реестр метрик не создан: {reason}")
            }
        }
    }
}

impl std::error::Error for ServerError {}

pub type Result<T> = std::result::Result<T, ServerError>;
