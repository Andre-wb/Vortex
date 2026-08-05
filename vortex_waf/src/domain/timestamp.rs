//! Момент времени в UTC.
//!
//! Собственный тип вместо `SystemTime` нужен, чтобы время можно было подменить
//! в тестах (см. `time::manual_clock`) и чтобы форматирование ISO-8601 не тянуло
//! за собой внешнюю зависимость.

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Timestamp {
    unix_millis: i64,
}

impl Timestamp {
    pub const fn from_unix_millis(unix_millis: i64) -> Self {
        Timestamp { unix_millis }
    }

    pub const fn from_unix_secs(unix_secs: i64) -> Self {
        Timestamp {
            unix_millis: unix_secs * 1000,
        }
    }

    pub const fn unix_millis(self) -> i64 {
        self.unix_millis
    }

    pub const fn unix_secs(self) -> i64 {
        self.unix_millis.div_euclid(1000)
    }

    pub fn plus_secs(self, secs: u64) -> Self {
        Timestamp {
            unix_millis: self
                .unix_millis
                .saturating_add((secs as i64).saturating_mul(1000)),
        }
    }

    pub fn minus_secs(self, secs: u64) -> Self {
        Timestamp {
            unix_millis: self
                .unix_millis
                .saturating_sub((secs as i64).saturating_mul(1000)),
        }
    }

    /// Разница в секундах: `self - earlier`. Отрицательна, если `self` раньше.
    pub fn secs_since(self, earlier: Timestamp) -> f64 {
        (self.unix_millis - earlier.unix_millis) as f64 / 1000.0
    }

    /// Представление вида `2026-08-04T12:30:00+00:00`.
    pub fn to_rfc3339(self) -> String {
        let secs = self.unix_secs();
        let days = secs.div_euclid(86_400);
        let secs_of_day = secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let hour = secs_of_day / 3600;
        let minute = (secs_of_day % 3600) / 60;
        let second = secs_of_day % 60;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Календарная дата из числа дней с 1970-01-01 (алгоритм Howard Hinnant).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::Timestamp;

    #[test]
    fn formats_epoch() {
        assert_eq!(
            Timestamp::from_unix_secs(0).to_rfc3339(),
            "1970-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn formats_known_moment() {
        // 2026-08-04T09:15:30Z
        assert_eq!(
            Timestamp::from_unix_secs(1_785_834_930).to_rfc3339(),
            "2026-08-04T09:15:30+00:00"
        );
        // Високосный год: 2024-02-29T12:00:00Z
        assert_eq!(
            Timestamp::from_unix_secs(1_709_208_000).to_rfc3339(),
            "2024-02-29T12:00:00+00:00"
        );
    }

    #[test]
    fn arithmetic_round_trips() {
        let t = Timestamp::from_unix_secs(1_000);
        assert_eq!(t.plus_secs(60).unix_secs(), 1_060);
        assert_eq!(t.minus_secs(60).unix_secs(), 940);
        assert!((t.plus_secs(30).secs_since(t) - 30.0).abs() < f64::EPSILON);
    }
}
