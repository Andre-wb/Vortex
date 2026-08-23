use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    Unconfigured,
    Connect(String),
    Query(String),
    OutOfRange(i64),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Unconfigured => write!(f, "Postgres не настроен"),
            StorageError::Connect(reason) => {
                write!(f, "не удалось подключиться к Postgres: {reason}")
            }
            StorageError::Query(reason) => write!(f, "запрос к Postgres не выполнен: {reason}"),
            StorageError::OutOfRange(value) => {
                write!(f, "идентификатор {value} не помещается в колонку integer")
            }
        }
    }
}

impl std::error::Error for StorageError {}

impl From<sqlx::Error> for StorageError {
    fn from(error: sqlx::Error) -> StorageError {
        StorageError::Query(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[cfg(test)]
mod tests {
    use super::StorageError;

    #[test]
    fn every_failure_names_postgres_in_its_message() {
        let failures = [
            StorageError::Unconfigured,
            StorageError::Connect("отказано".to_string()),
            StorageError::Query("синтаксис".to_string()),
        ];
        for failure in failures {
            assert!(failure.to_string().contains("Postgres"));
        }
    }

    #[test]
    fn an_overflowing_identifier_names_the_value_it_refused() {
        assert!(StorageError::OutOfRange(i64::MAX)
            .to_string()
            .contains(&i64::MAX.to_string()));
    }
}
