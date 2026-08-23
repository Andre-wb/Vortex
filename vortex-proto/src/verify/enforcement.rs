#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    Reject,
    WarnOnly,
}

impl Enforcement {
    pub fn from_flag(enforce: bool) -> Self {
        if enforce {
            Enforcement::Reject
        } else {
            Enforcement::WarnOnly
        }
    }

    pub fn rejects(&self) -> bool {
        matches!(self, Enforcement::Reject)
    }
}

#[cfg(test)]
mod tests {
    use super::Enforcement;

    #[test]
    fn the_flag_decides_whether_a_complaint_stops_the_publish() {
        assert!(Enforcement::from_flag(true).rejects());
        assert!(!Enforcement::from_flag(false).rejects());
    }
}
