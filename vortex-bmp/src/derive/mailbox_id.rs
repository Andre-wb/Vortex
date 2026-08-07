use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::rotation::RotationConfig;
use crate::derive::epoch::{epoch_at, epoch_span};
use crate::derive::jitter::pair_jitter;
use crate::mailbox::id::MailboxId;
use crate::secret::value::BmpSecret;

const ID_BYTES: usize = 16;

pub fn mailbox_id_for_epoch(secret: &BmpSecret, epoch: u64) -> MailboxId {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.bytes()).expect("HMAC принимает любой ключ");
    mac.update(&epoch.to_be_bytes());
    let signature = mac.finalize().into_bytes();
    MailboxId::parse(&hex::encode(&signature[..ID_BYTES])).expect("шестнадцатеричный идентификатор")
}

pub fn mailbox_id_at(secret: &BmpSecret, rotation: RotationConfig, timestamp: f64) -> MailboxId {
    let jitter = pair_jitter(secret, rotation.jitter_secs);
    let epoch = epoch_at(timestamp, jitter, rotation.period_secs).max(0) as u64;
    mailbox_id_for_epoch(secret, epoch)
}

pub fn mailbox_ids_at(
    secret: &BmpSecret,
    rotation: RotationConfig,
    timestamp: f64,
) -> Vec<MailboxId> {
    let jitter = pair_jitter(secret, rotation.jitter_secs);
    let epoch = epoch_at(timestamp, jitter, rotation.period_secs);
    epoch_span(epoch, rotation.clock_skew_epochs)
        .map(|candidate| mailbox_id_for_epoch(secret, candidate))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{mailbox_id_at, mailbox_ids_at};
    use crate::config::rotation::RotationConfig;
    use crate::secret::value::BmpSecret;

    fn secret(byte: &str) -> BmpSecret {
        BmpSecret::parse(&byte.repeat(32)).unwrap()
    }

    #[test]
    fn an_identifier_is_sixteen_bytes_of_hex() {
        let id = mailbox_id_at(&secret("ab"), RotationConfig::default(), 1_000_000.0);
        assert_eq!(id.as_str().len(), 32);
    }

    #[test]
    fn the_identifier_holds_still_inside_one_epoch() {
        let rotation = RotationConfig::default();
        assert_eq!(
            mailbox_id_at(&secret("11"), rotation, 1_000.0),
            mailbox_id_at(&secret("11"), rotation, 1_001.0)
        );
    }

    #[test]
    fn the_identifier_changes_once_the_epoch_turns() {
        let rotation = RotationConfig::default();
        assert_ne!(
            mailbox_id_at(&secret("cd"), rotation, 0.0),
            mailbox_id_at(&secret("cd"), rotation, 7200.0)
        );
    }

    #[test]
    fn two_pairs_never_share_a_mailbox() {
        let rotation = RotationConfig::default();
        assert_ne!(
            mailbox_id_at(&secret("ab"), rotation, 1_700_000_000.0),
            mailbox_id_at(&secret("cd"), rotation, 1_700_000_000.0)
        );
    }

    #[test]
    fn the_skew_window_spans_three_epochs() {
        let ids = mailbox_ids_at(&secret("ef"), RotationConfig::default(), 100_000.0);
        assert_eq!(ids.len(), 3);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
    }

    #[test]
    fn the_middle_of_the_skew_window_is_the_current_mailbox() {
        let rotation = RotationConfig::default();
        let ids = mailbox_ids_at(&secret("ef"), rotation, 100_000.0);
        assert_eq!(ids[1], mailbox_id_at(&secret("ef"), rotation, 100_000.0));
    }

    #[test]
    fn the_first_epoch_repeats_its_identifier_instead_of_reaching_below_zero() {
        let ids = mailbox_ids_at(&secret("ab"), RotationConfig::default(), 1.0);
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
    }
}
