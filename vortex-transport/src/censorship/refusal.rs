use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Region,
    NoTransports,
    AtCapacity,
}

impl Refusal {
    pub fn status(&self) -> u16 {
        match self {
            Refusal::Region | Refusal::NoTransports => 400,
            Refusal::AtCapacity => 503,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Refusal::Region => "region",
            Refusal::NoTransports => "no_transports",
            Refusal::AtCapacity => "at_capacity",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Region => write!(f, "имя региона непредставимо"),
            Refusal::NoTransports => {
                write!(f, "отчёт не называет ни одного известного транспорта")
            }
            Refusal::AtCapacity => write!(f, "панель уже держит предельное число регионов"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Refusal;

    #[test]
    fn a_bad_report_is_the_fault_of_the_client_and_a_full_panel_is_not() {
        assert_eq!(Refusal::Region.status(), 400);
        assert_eq!(Refusal::NoTransports.status(), 400);
        assert_eq!(Refusal::AtCapacity.status(), 503);
    }

    #[test]
    fn every_refusal_has_a_name_that_is_not_the_value_it_refused() {
        for refusal in [Refusal::Region, Refusal::NoTransports, Refusal::AtCapacity] {
            assert!(!refusal.as_str().is_empty());
            assert!(!refusal.to_string().is_empty());
        }
    }
}
