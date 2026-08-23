use crate::error::{Result, StorageError};

pub fn column_id(value: i64) -> Result<i32> {
    i32::try_from(value).map_err(|_| StorageError::OutOfRange(value))
}

pub fn optional_column_id(value: Option<i64>) -> Result<Option<i32>> {
    match value {
        Some(value) => column_id(value).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{column_id, optional_column_id};
    use crate::error::StorageError;

    #[test]
    fn an_identifier_inside_the_column_passes_through() {
        assert_eq!(column_id(0), Ok(0));
        assert_eq!(column_id(i32::MAX as i64), Ok(i32::MAX));
        assert_eq!(column_id(i32::MIN as i64), Ok(i32::MIN));
    }

    #[test]
    fn an_identifier_wider_than_the_column_is_refused_rather_than_wrapped() {
        let too_big = i32::MAX as i64 + 1;
        assert_eq!(column_id(too_big), Err(StorageError::OutOfRange(too_big)));
        let too_small = i32::MIN as i64 - 1;
        assert_eq!(
            column_id(too_small),
            Err(StorageError::OutOfRange(too_small))
        );
    }

    #[test]
    fn an_absent_identifier_stays_absent() {
        assert_eq!(optional_column_id(None), Ok(None));
        assert_eq!(optional_column_id(Some(7)), Ok(Some(7)));
    }
}
