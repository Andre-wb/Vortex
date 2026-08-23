use crate::flood::limits::BAN_STRIKES;

pub fn earns_a_ban(strikes: u32) -> bool {
    strikes >= BAN_STRIKES
}

#[cfg(test)]
mod tests {
    use super::earns_a_ban;

    #[test]
    fn the_first_two_penalties_leave_the_configured_answer_alone() {
        assert!(!earns_a_ban(0));
        assert!(!earns_a_ban(1));
        assert!(!earns_a_ban(2));
    }

    #[test]
    fn the_third_penalty_overrides_the_configured_answer() {
        assert!(earns_a_ban(3));
        assert!(earns_a_ban(4));
    }
}
