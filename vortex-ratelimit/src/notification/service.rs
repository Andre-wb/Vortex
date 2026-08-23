use std::sync::Arc;

use crate::attempt::counting::judge;
use crate::attempt::member::Member;
use crate::attempt::verdict::Verdict;
use crate::notification::limits::{pair_limit, sender_limit, window};
use crate::ports::attempt_limiter::AttemptLimiter;

pub const SENDER_BUCKET: &str = "notification-sender";
pub const PAIR_BUCKET: &str = "notification-pair";

pub struct NotificationRateService {
    attempts: Arc<dyn AttemptLimiter>,
}

impl NotificationRateService {
    pub fn new(attempts: Arc<dyn AttemptLimiter>) -> Self {
        NotificationRateService { attempts }
    }

    pub fn allow_from(&self, sender_id: i64, now: f64) -> Verdict {
        judge(
            &self.attempts,
            SENDER_BUCKET,
            &Member::of_account(sender_id),
            sender_limit(),
            window(),
            now,
        )
    }

    pub fn allow_to(&self, sender_id: i64, recipient_id: i64, now: f64) -> Verdict {
        judge(
            &self.attempts,
            PAIR_BUCKET,
            &Member::of_pair(sender_id, recipient_id),
            pair_limit(),
            window(),
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::NotificationRateService;
    use crate::attempt::memory::MemoryAttemptLimiter;
    use crate::attempt::unavailable::UnavailableAttemptLimiter;
    use crate::attempt::verdict::Verdict;

    const NOW: f64 = 1_000.0;

    fn service() -> NotificationRateService {
        NotificationRateService::new(Arc::new(MemoryAttemptLimiter::new()))
    }

    #[test]
    fn sixty_notifications_a_minute_pass_and_the_sixty_first_does_not() {
        let service = service();
        for index in 0..60 {
            assert_eq!(service.allow_from(7, NOW), Verdict::Allowed, "{index}");
        }
        assert_eq!(service.allow_from(7, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn twenty_notifications_to_one_recipient_pass_and_the_twenty_first_does_not() {
        let service = service();
        for _ in 0..20 {
            assert_eq!(service.allow_to(7, 9, NOW), Verdict::Allowed);
        }
        assert_eq!(service.allow_to(7, 9, NOW), Verdict::OverTheLimit);
    }

    #[test]
    fn one_recipient_never_spends_the_budget_of_another() {
        let service = service();
        for _ in 0..20 {
            service.allow_to(7, 9, NOW);
        }
        assert_eq!(service.allow_to(7, 10, NOW), Verdict::Allowed);
    }

    #[test]
    fn the_sender_window_and_the_pair_window_are_counted_apart() {
        let service = service();
        for _ in 0..20 {
            service.allow_to(7, 9, NOW);
        }
        assert_eq!(service.allow_from(7, NOW), Verdict::Allowed);
    }

    #[test]
    fn a_notification_nobody_can_count_is_refused_rather_than_waved_through() {
        let service = NotificationRateService::new(Arc::new(UnavailableAttemptLimiter::new()));
        assert_eq!(service.allow_from(7, NOW), Verdict::Unavailable);
        assert_eq!(service.allow_to(7, 9, NOW), Verdict::Unavailable);
    }
}
