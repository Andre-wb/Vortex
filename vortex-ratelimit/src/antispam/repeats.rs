use std::sync::Arc;

use crate::antispam::digest::Digest;
use crate::antispam::limits::{repeat_window, repeats};
use crate::antispam::outcome::SpamOutcome;
use crate::attempt::membership::Membership;
use crate::attempt::subject::Subject;
use crate::ports::repeat_ledger::RepeatLedger;
use crate::ports::window_reset::WindowReset;

pub const BUCKET: &str = "antispam-repeats";

pub struct RepeatSpamService {
    seen: Arc<dyn RepeatLedger>,
    reset: Arc<dyn WindowReset>,
}

impl RepeatSpamService {
    pub fn new(seen: Arc<dyn RepeatLedger>, reset: Arc<dyn WindowReset>) -> Self {
        RepeatSpamService { seen, reset }
    }

    pub fn judge(&self, membership: Membership, text: &str, now: f64) -> SpamOutcome {
        let subject = Subject::of(BUCKET, membership.member().as_str());
        let digest = Digest::of(text);

        match self.seen.record(&subject, &digest, repeat_window(), now) {
            Err(_) => SpamOutcome::Unavailable,
            Ok(same) if same >= repeats() => {
                let _ = self.reset.forget(&subject);
                SpamOutcome::Spam
            }
            Ok(_) => SpamOutcome::Clean,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::RepeatSpamService;
    use crate::antispam::memory::MemoryRepeatLedger;
    use crate::antispam::outcome::SpamOutcome;
    use crate::antispam::unavailable::UnavailableRepeatLedger;
    use crate::attempt::membership::Membership;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;

    const NOW: f64 = 1_000.0;

    fn service() -> RepeatSpamService {
        let ledger = Arc::new(MemoryRepeatLedger::new());
        RepeatSpamService::new(ledger.clone(), ledger)
    }

    #[test]
    fn two_copies_pass_and_the_third_is_spam() {
        let service = service();
        let membership = Membership::of(1, 7);
        assert_eq!(service.judge(membership, "stop", NOW), SpamOutcome::Clean);
        assert_eq!(service.judge(membership, "stop", NOW), SpamOutcome::Clean);
        assert_eq!(service.judge(membership, "stop", NOW), SpamOutcome::Spam);
    }

    #[test]
    fn different_messages_never_add_up_to_a_repeat() {
        let service = service();
        let membership = Membership::of(1, 7);
        for text in ["one", "two", "three", "four"] {
            assert_eq!(service.judge(membership, text, NOW), SpamOutcome::Clean);
        }
    }

    #[test]
    fn a_copy_outside_the_window_starts_the_count_again() {
        let service = service();
        let membership = Membership::of(1, 7);
        service.judge(membership, "stop", NOW);
        service.judge(membership, "stop", NOW);
        assert_eq!(
            service.judge(membership, "stop", NOW + 30.0),
            SpamOutcome::Clean
        );
    }

    #[test]
    fn a_caught_member_starts_from_scratch_including_messages_it_never_repeated() {
        let service = service();
        let membership = Membership::of(1, 7);
        service.judge(membership, "other", NOW);
        service.judge(membership, "stop", NOW);
        service.judge(membership, "stop", NOW);
        assert_eq!(service.judge(membership, "stop", NOW), SpamOutcome::Spam);
        for _ in 0..2 {
            assert_eq!(service.judge(membership, "other", NOW), SpamOutcome::Clean);
        }
    }

    #[test]
    fn one_member_never_answers_for_another() {
        let service = service();
        service.judge(Membership::of(1, 7), "stop", NOW);
        service.judge(Membership::of(1, 7), "stop", NOW);
        assert_eq!(
            service.judge(Membership::of(1, 8), "stop", NOW),
            SpamOutcome::Clean
        );
        assert_eq!(
            service.judge(Membership::of(2, 7), "stop", NOW),
            SpamOutcome::Clean
        );
    }

    #[test]
    fn letter_case_and_surrounding_space_do_not_hide_a_repeat() {
        let service = service();
        let membership = Membership::of(1, 7);
        service.judge(membership, "Stop", NOW);
        service.judge(membership, "  STOP ", NOW);
        assert_eq!(service.judge(membership, "stop", NOW), SpamOutcome::Spam);
    }

    #[test]
    fn a_message_nobody_can_count_is_held_back_rather_than_waved_through() {
        let service = RepeatSpamService::new(
            Arc::new(UnavailableRepeatLedger::new()),
            Arc::new(UnavailableAttemptLimiter::new()),
        );
        assert_eq!(
            service.judge(Membership::of(1, 7), "stop", NOW),
            SpamOutcome::Unavailable
        );
    }
}
