use crate::attempt::refusal::MemberRefusal;

pub const MAX_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Member(String);

impl Member {
    pub fn parse(value: &str) -> Result<Self, MemberRefusal> {
        if value.is_empty() {
            return Err(MemberRefusal::Empty);
        }
        if value.len() > MAX_LEN {
            return Err(MemberRefusal::TooLong {
                max: MAX_LEN,
                got: value.len(),
            });
        }
        if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(MemberRefusal::NotPrintable);
        }
        Ok(Member(value.to_owned()))
    }

    pub fn of_account(user_id: i64) -> Self {
        Member(user_id.to_string())
    }

    pub fn of_pair(sender: i64, recipient: i64) -> Self {
        Member(format!("{sender}:{recipient}"))
    }

    pub fn everyone() -> Self {
        Member("all".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Member, MAX_LEN};
    use crate::attempt::refusal::MemberRefusal;

    #[test]
    fn an_address_a_node_name_and_a_pair_are_all_members() {
        for value in ["10.0.0.1", "fe80::1%lo0", "node-7", "12:34"] {
            assert_eq!(Member::parse(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn a_member_nobody_named_is_refused() {
        assert_eq!(Member::parse(""), Err(MemberRefusal::Empty));
    }

    #[test]
    fn a_member_longer_than_any_identifier_is_refused() {
        let long = "a".repeat(MAX_LEN + 1);
        assert_eq!(
            Member::parse(&long),
            Err(MemberRefusal::TooLong {
                max: MAX_LEN,
                got: MAX_LEN + 1
            })
        );
    }

    #[test]
    fn whitespace_and_control_characters_never_travel_inside_a_member() {
        for hostile in ["node 7", "node\n7", "node\u{0}7"] {
            assert_eq!(Member::parse(hostile), Err(MemberRefusal::NotPrintable));
        }
    }

    #[test]
    fn an_account_is_counted_under_its_own_number() {
        assert_eq!(Member::of_account(7).as_str(), "7");
        assert_eq!(Member::of_pair(7, 9).as_str(), "7:9");
    }

    #[test]
    fn a_limit_shared_by_everyone_has_one_member() {
        assert_eq!(Member::everyone().as_str(), "all");
    }
}
