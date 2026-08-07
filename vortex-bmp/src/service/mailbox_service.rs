use std::sync::Arc;

use crate::config::rate::RateConfig;
use crate::config::rotation::RotationConfig;
use crate::config::storage::StorageConfig;
use crate::derive::mailbox_id::{mailbox_id_at, mailbox_ids_at};
use crate::mailbox::id::MailboxId;
use crate::padding::response::response_padding;
use crate::ports::clock::Clock;
use crate::ports::mailbox_store::MailboxStore;
use crate::ports::random_source::RandomSource;
use crate::ports::rate_limiter::RateLimiter;
use crate::ports::room_secrets::RoomSecrets;
use crate::ratelimit::class::RateClass;
use crate::rejection::Rejection;
use crate::secret::value::BmpSecret;
use crate::service::outcome::{BatchOutcome, EnvelopeOutcome};
use crate::store::stats::StoreStats;
use crate::wake::category::wake_category;

pub struct BmpService {
    store: Arc<dyn MailboxStore>,
    secrets: Arc<dyn RoomSecrets>,
    limiter: Arc<dyn RateLimiter>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
    storage: StorageConfig,
    rotation: RotationConfig,
    rate: RateConfig,
}

impl BmpService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<dyn MailboxStore>,
        secrets: Arc<dyn RoomSecrets>,
        limiter: Arc<dyn RateLimiter>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
        storage: StorageConfig,
        rotation: RotationConfig,
        rate: RateConfig,
    ) -> Self {
        BmpService {
            store,
            secrets,
            limiter,
            random,
            clock,
            storage,
            rotation,
            rate,
        }
    }

    pub fn storage(&self) -> StorageConfig {
        self.storage
    }

    pub fn rotation(&self) -> RotationConfig {
        self.rotation
    }

    pub fn rate(&self) -> RateConfig {
        self.rate
    }

    fn allowed(&self, class: RateClass, client: &str) -> bool {
        self.limiter
            .allow(&class.window_key(client), class.limit(&self.rate))
    }

    pub fn deposit(&self, mailbox_id: &str, ciphertext: &str, client: &str) -> Option<Rejection> {
        let mailbox = match MailboxId::parse(mailbox_id) {
            Ok(mailbox) => mailbox,
            Err(error) => return Some(Rejection::invalid_mailbox_id(&error)),
        };
        if !self.allowed(RateClass::Standard, client) {
            return Some(Rejection::rate_limited());
        }
        if ciphertext.len() < self.storage.min_ciphertext_chars {
            return Some(Rejection::message_too_short(
                self.storage.min_ciphertext_chars,
            ));
        }
        match self.store.deposit(&mailbox, ciphertext) {
            Ok(()) => None,
            Err(refusal) => Some(Rejection::refused_deposit(refusal)),
        }
    }

    pub fn fetch_batch(
        &self,
        mailbox_ids: &[String],
        since: f64,
        client: &str,
        class: RateClass,
    ) -> Result<BatchOutcome, Rejection> {
        if !self.allowed(class, client) {
            return Err(Rejection::rate_limited());
        }
        let requested: Vec<MailboxId> = mailbox_ids
            .iter()
            .take(self.storage.max_batch)
            .filter_map(|candidate| MailboxId::parse(candidate).ok())
            .collect();

        Ok(BatchOutcome {
            mailboxes: self.store.fetch_batch(&requested, since),
            padding: response_padding(self.random.as_ref()),
        })
    }

    pub fn register_room_secret(&self, room_id: i64, secret_hex: &str) -> Option<Rejection> {
        match BmpSecret::parse(secret_hex) {
            Ok(secret) => {
                self.secrets.set(room_id, secret);
                None
            }
            Err(error) => Some(Rejection::invalid_secret(&error)),
        }
    }

    pub fn room_secret(&self, room_id: i64) -> Option<String> {
        self.secrets.get(room_id).map(|secret| secret.to_hex())
    }

    pub fn forget_room_secret(&self, room_id: i64) {
        self.secrets.remove(room_id);
    }

    pub fn deposit_envelope(&self, room_id: i64, envelope: &str) -> EnvelopeOutcome {
        let Some(secret) = self.secrets.get(room_id) else {
            return EnvelopeOutcome::UnknownRoom;
        };

        let now = self.clock.unix_seconds();
        let mailboxes = mailbox_ids_at(&secret, self.rotation, now);

        let mut deposited = Vec::new();
        let mut wake_categories = Vec::new();
        let mut refusal = None;
        for mailbox in mailboxes {
            match self.store.deposit(&mailbox, envelope) {
                Ok(()) => {
                    wake_categories.push(wake_category(&mailbox));
                    deposited.push(mailbox);
                }
                Err(reason) => refusal = Some(reason),
            }
        }

        if deposited.is_empty() {
            return match refusal {
                Some(reason) => EnvelopeOutcome::Refused(reason),
                None => EnvelopeOutcome::UnknownRoom,
            };
        }

        EnvelopeOutcome::Deposited {
            mailboxes: deposited,
            wake_categories,
        }
    }

    pub fn mailbox_id_for_room(&self, room_id: i64, timestamp: Option<f64>) -> Option<MailboxId> {
        let secret = self.secrets.get(room_id)?;
        Some(mailbox_id_at(
            &secret,
            self.rotation,
            timestamp.unwrap_or_else(|| self.clock.unix_seconds()),
        ))
    }

    pub fn collect_garbage(&self) -> u64 {
        let removed = self.store.collect_garbage();
        self.limiter.forget_stale();
        removed
    }

    pub fn stats(&self) -> StoreStats {
        self.store.stats()
    }

    pub fn tracked_rate_keys(&self) -> usize {
        self.limiter.tracked_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::BmpService;
    use crate::config::rate::RateConfig;
    use crate::config::storage::StorageConfig;
    use crate::ratelimit::class::RateClass;
    use crate::secret::value::BmpSecret;
    use crate::service::builder::BmpServiceBuilder;
    use crate::service::outcome::EnvelopeOutcome;
    use crate::store::refusal::DepositRefusal;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    const NOW: f64 = 1_700_000_000.0;
    const ROOM: i64 = 7;
    const SECRET: &str = "ab";
    const CIPHERTEXT: &str = "abababababababababababab";

    fn service_with(clock: Arc<ManualClock>) -> BmpService {
        BmpServiceBuilder::new().with_clock(clock).build()
    }

    fn service() -> BmpService {
        service_with(Arc::new(ManualClock::at(NOW)))
    }

    fn secret_hex() -> String {
        SECRET.repeat(32)
    }

    #[test]
    fn a_deposit_into_a_valid_mailbox_is_accepted() {
        let service = service();
        assert_eq!(
            service.deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4"),
            None
        );
    }

    #[test]
    fn a_deposit_into_a_malformed_mailbox_is_refused_before_the_rate_limit() {
        let service = service();
        assert_eq!(
            service
                .deposit("abc", CIPHERTEXT, "1.2.3.4")
                .unwrap()
                .status,
            400
        );
        assert_eq!(service.tracked_rate_keys(), 0);
    }

    #[test]
    fn a_deposit_shorter_than_the_minimum_is_refused() {
        let service = service();
        let rejection = service
            .deposit("0123456789abcdef", "aabb", "1.2.3.4")
            .unwrap();
        assert_eq!(rejection.status, 400);
        assert_eq!(service.stats().total_deposited, 0);
    }

    #[test]
    fn an_envelope_is_never_measured_against_the_minimum_request_size() {
        let service = service();
        service.register_room_secret(ROOM, &secret_hex());
        assert!(service.deposit_envelope(ROOM, "aabb").is_deposited());
    }

    #[test]
    fn a_client_over_the_limit_is_refused() {
        let service = BmpServiceBuilder::new()
            .with_rate(RateConfig::default().standard_per_window(2))
            .build();
        assert!(service
            .deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4")
            .is_none());
        assert!(service
            .deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4")
            .is_none());
        assert_eq!(
            service
                .deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4")
                .unwrap()
                .status,
            429
        );
    }

    #[test]
    fn fast_polling_gets_its_own_ceiling() {
        let service = BmpServiceBuilder::new()
            .with_rate(
                RateConfig::default()
                    .standard_per_window(1)
                    .fast_per_window(3),
            )
            .build();
        let ids = vec!["0123456789abcdef".to_string()];
        assert!(service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Fast)
            .is_ok());
        assert!(service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Fast)
            .is_ok());
        assert!(service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Fast)
            .is_ok());
        assert!(service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Fast)
            .is_err());
    }

    #[test]
    fn fast_polling_never_spends_the_standard_budget() {
        let service = BmpServiceBuilder::new()
            .with_rate(
                RateConfig::default()
                    .standard_per_window(1)
                    .fast_per_window(2),
            )
            .build();
        let ids = vec!["0123456789abcdef".to_string()];
        assert!(service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Fast)
            .is_ok());
        assert!(service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Fast)
            .is_ok());
        assert!(service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Fast)
            .is_err());
        assert!(service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Standard)
            .is_ok());
        assert!(service
            .deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4")
            .is_some());
    }

    #[test]
    fn depositing_and_fetching_share_the_standard_window() {
        let service = BmpServiceBuilder::new()
            .with_rate(RateConfig::default().standard_per_window(1))
            .build();
        assert!(service
            .deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4")
            .is_none());
        assert!(service
            .fetch_batch(&[], 0.0, "1.2.3.4", RateClass::Standard)
            .is_err());
    }

    #[test]
    fn an_envelope_is_deposited_even_when_the_client_window_is_exhausted() {
        let service = BmpServiceBuilder::new()
            .with_rate(RateConfig::default().standard_per_window(1))
            .build();
        service.register_room_secret(ROOM, &secret_hex());
        assert!(service
            .deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4")
            .is_none());
        assert!(service
            .deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4")
            .is_some());
        assert!(service.deposit_envelope(ROOM, CIPHERTEXT).is_deposited());
    }

    #[test]
    fn a_batch_never_reads_more_mailboxes_than_the_limit_allows() {
        let service = BmpServiceBuilder::new()
            .with_storage(StorageConfig::default().max_batch(2))
            .build();
        for seed in 0..3u8 {
            service.deposit(&format!("{seed:0>16}"), CIPHERTEXT, "1.2.3.4");
        }
        let ids: Vec<String> = (0..3u8).map(|seed| format!("{seed:0>16}")).collect();
        let outcome = service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Standard)
            .unwrap();
        assert_eq!(outcome.mailboxes.len(), 2);
    }

    #[test]
    fn a_malformed_mailbox_in_a_batch_is_skipped_rather_than_failing_the_request() {
        let service = service();
        service.deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4");
        let ids = vec!["zzz".to_string(), "0123456789abcdef".to_string()];
        let outcome = service
            .fetch_batch(&ids, 0.0, "1.2.3.4", RateClass::Standard)
            .unwrap();
        assert_eq!(outcome.mailboxes.len(), 1);
    }

    #[test]
    fn every_batch_carries_padding() {
        let service = service();
        let outcome = service
            .fetch_batch(&[], 0.0, "1.2.3.4", RateClass::Standard)
            .unwrap();
        assert!(outcome.mailboxes.is_empty());
        assert!(outcome.padding.len() >= 170);
    }

    #[test]
    fn an_envelope_lands_in_every_mailbox_of_the_skew_window() {
        let service = service();
        service.register_room_secret(ROOM, &secret_hex());
        let outcome = service.deposit_envelope(ROOM, CIPHERTEXT);
        match outcome {
            EnvelopeOutcome::Deposited {
                mailboxes,
                wake_categories,
            } => {
                assert_eq!(mailboxes.len(), 3);
                assert_eq!(wake_categories.len(), 3);
            }
            other => panic!("ожидался депозит, получено {other:?}"),
        }
    }

    #[test]
    fn an_envelope_for_an_unregistered_room_is_reported_as_such() {
        let service = service();
        assert_eq!(
            service.deposit_envelope(ROOM, CIPHERTEXT),
            EnvelopeOutcome::UnknownRoom
        );
    }

    #[test]
    fn an_envelope_is_readable_from_the_mailbox_the_client_derives() {
        let clock = Arc::new(ManualClock::at(NOW));
        let service = service_with(clock);
        service.register_room_secret(ROOM, &secret_hex());
        service.deposit_envelope(ROOM, CIPHERTEXT);

        let expected = crate::derive::mailbox_id::mailbox_id_at(
            &BmpSecret::parse(&secret_hex()).unwrap(),
            service.rotation(),
            NOW,
        );
        let outcome = service
            .fetch_batch(
                &[expected.as_str().to_string()],
                0.0,
                "1.2.3.4",
                RateClass::Standard,
            )
            .unwrap();
        assert_eq!(outcome.mailboxes.len(), 1);
        assert_eq!(outcome.mailboxes[0].1[0].ciphertext(), CIPHERTEXT);
    }

    #[test]
    fn an_envelope_refused_by_a_full_store_is_reported_instead_of_looking_delivered() {
        let service = BmpServiceBuilder::new()
            .with_storage(StorageConfig::default().max_stored_bytes(0))
            .build();
        service.register_room_secret(ROOM, &secret_hex());
        assert_eq!(
            service.deposit_envelope(ROOM, CIPHERTEXT),
            EnvelopeOutcome::Refused(DepositRefusal::AtCapacity)
        );
    }

    #[test]
    fn a_room_secret_that_is_not_hex_is_refused_when_it_is_registered() {
        let service = service();
        let rejection = service
            .register_room_secret(ROOM, &"zz".repeat(32))
            .unwrap();
        assert_eq!(rejection.status, 400);
        assert_eq!(service.room_secret(ROOM), None);
    }

    #[test]
    fn a_room_secret_of_the_wrong_length_is_refused() {
        let service = service();
        assert!(service.register_room_secret(ROOM, "aabb").is_some());
    }

    #[test]
    fn a_registered_secret_can_be_read_back_and_forgotten() {
        let service = service();
        service.register_room_secret(ROOM, &secret_hex());
        assert_eq!(service.room_secret(ROOM), Some(secret_hex()));
        service.forget_room_secret(ROOM);
        assert_eq!(service.room_secret(ROOM), None);
    }

    #[test]
    fn a_forgotten_room_stops_accepting_envelopes() {
        let service = service();
        service.register_room_secret(ROOM, &secret_hex());
        service.forget_room_secret(ROOM);
        assert_eq!(
            service.deposit_envelope(ROOM, CIPHERTEXT),
            EnvelopeOutcome::UnknownRoom
        );
    }

    #[test]
    fn maintenance_reclaims_expired_messages_and_stale_rate_keys() {
        let clock = Arc::new(ManualClock::at(NOW));
        let service = service_with(clock.clone());
        service.deposit("0123456789abcdef", CIPHERTEXT, "1.2.3.4");
        assert_eq!(service.tracked_rate_keys(), 1);
        clock.advance(7200.0);
        assert_eq!(service.collect_garbage(), 1);
        assert_eq!(service.tracked_rate_keys(), 0);
        assert_eq!(service.stats().active_mailboxes, 0);
    }
}
