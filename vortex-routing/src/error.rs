use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    Unavailable,
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoutingError::Unavailable => {
                write!(f, "общий стор пер-роут флагов недоступен")
            }
        }
    }
}

impl std::error::Error for RoutingError {}

pub type Result<T> = std::result::Result<T, RoutingError>;
