use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRefusal {
    NotAnAddress,
    PortOutsideRange,
    EmptyName,
    OverLongName,
    NameOutsideAlphabet,
    OverLongRoomsDocument,
}

impl fmt::Display for PeerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerRefusal::NotAnAddress => write!(f, "адрес узла не является IP-адресом"),
            PeerRefusal::PortOutsideRange => write!(f, "порт узла должен быть от 1 до 65535"),
            PeerRefusal::EmptyName => write!(f, "имя узла пусто"),
            PeerRefusal::OverLongName => write!(
                f,
                "имя узла длиннее {} символов",
                super::limits::MAX_NAME_LENGTH
            ),
            PeerRefusal::NameOutsideAlphabet => {
                write!(f, "имя узла содержит двоеточие или управляющий символ")
            }
            PeerRefusal::OverLongRoomsDocument => write!(
                f,
                "перечень комнат узла длиннее {} символов",
                super::limits::MAX_ROOMS_DOCUMENT
            ),
        }
    }
}

impl std::error::Error for PeerRefusal {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    Unavailable,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::Unavailable => {
                write!(f, "общий реестр узлов недоступен — операция не выполнена")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

pub type Result<T> = std::result::Result<T, RegistryError>;
