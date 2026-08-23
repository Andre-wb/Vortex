use time::{OffsetDateTime, PrimitiveDateTime};

use crate::error::{Result, StorageError};

pub const MICROS_PER_SECOND: u32 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp {
    reading: PrimitiveDateTime,
}

impl Stamp {
    pub fn from_unix(seconds: i64, micros: u32) -> Result<Stamp> {
        if micros >= MICROS_PER_SECOND {
            return Err(StorageError::OutOfRange(i64::from(micros)));
        }
        let whole = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(|_| StorageError::OutOfRange(seconds))?;
        let exact = whole
            .replace_microsecond(micros)
            .map_err(|_| StorageError::OutOfRange(i64::from(micros)))?;
        Ok(Stamp {
            reading: PrimitiveDateTime::new(exact.date(), exact.time()),
        })
    }

    pub fn unix_seconds(&self) -> i64 {
        self.reading.assume_utc().unix_timestamp()
    }

    pub fn micros(&self) -> u32 {
        self.reading.microsecond()
    }

    pub(crate) fn from_reading(reading: PrimitiveDateTime) -> Stamp {
        Stamp { reading }
    }

    pub(crate) fn reading(&self) -> PrimitiveDateTime {
        self.reading
    }
}

#[cfg(test)]
mod tests {
    use super::Stamp;
    use crate::error::StorageError;

    #[test]
    fn a_reading_survives_a_round_trip_to_the_microsecond() {
        for (seconds, micros) in [
            (0_i64, 0_u32),
            (1_785_834_930, 715_103),
            (1_785_834_930, 999_999),
            (2_147_483_647, 1),
        ] {
            let stamp = Stamp::from_unix(seconds, micros).expect("отметка не собралась");
            assert_eq!((stamp.unix_seconds(), stamp.micros()), (seconds, micros));
        }
    }

    #[test]
    fn a_reading_before_the_epoch_keeps_its_fraction() {
        let stamp = Stamp::from_unix(-1, 500_000).expect("отметка не собралась");
        assert_eq!((stamp.unix_seconds(), stamp.micros()), (-1, 500_000));
    }

    #[test]
    fn a_fraction_of_a_whole_second_or_more_is_refused() {
        assert_eq!(
            Stamp::from_unix(0, 1_000_000),
            Err(StorageError::OutOfRange(1_000_000))
        );
    }

    #[test]
    fn readings_order_by_the_moment_they_name() {
        let earlier = Stamp::from_unix(1_785_834_930, 1).expect("отметка не собралась");
        let later = Stamp::from_unix(1_785_834_930, 2).expect("отметка не собралась");
        assert!(earlier < later);
    }
}
