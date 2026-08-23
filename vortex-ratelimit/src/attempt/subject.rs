#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Subject {
    bucket: &'static str,
    member: String,
}

impl Subject {
    pub fn of(bucket: &'static str, member: impl Into<String>) -> Self {
        Subject {
            bucket,
            member: member.into(),
        }
    }

    pub fn bucket(&self) -> &'static str {
        self.bucket
    }

    pub fn member(&self) -> &str {
        &self.member
    }
}

#[cfg(test)]
mod tests {
    use super::Subject;

    #[test]
    fn a_subject_names_the_bucket_it_is_counted_in() {
        let subject = Subject::of("entry-attempts", "10.0.0.1");
        assert_eq!(subject.bucket(), "entry-attempts");
        assert_eq!(subject.member(), "10.0.0.1");
    }

    #[test]
    fn one_member_counted_in_two_buckets_is_two_subjects() {
        let entry = Subject::of("entry-attempts", "7");
        let totp = Subject::of("totp-attempts", "7");
        assert_ne!(entry, totp);
    }

    #[test]
    fn an_address_with_colons_stays_one_member() {
        let subject = Subject::of("entry-attempts", "fe80::1");
        assert_eq!(subject.member(), "fe80::1");
        assert_ne!(subject, Subject::of("entry-attempts", "fe80::2"));
    }
}
