use std::sync::Arc;

use crate::dedup::service::DeduplicationService;
use crate::message::identifier::MessageId;
use crate::ports::seen_messages::SeenMessages;

fn id(text: &str) -> MessageId {
    MessageId::parse(text).expect("идентификатор должен разбираться")
}

pub fn a_first_sighting_is_not_a_repeat(store: Arc<dyn SeenMessages>) {
    let service = DeduplicationService::new(store);
    assert!(!service.is_repeat(&id("conf-first"), 1000.0).unwrap());
}

pub fn a_second_sighting_is_a_repeat(store: Arc<dyn SeenMessages>) {
    let service = DeduplicationService::new(store);
    assert!(!service.is_repeat(&id("conf-second"), 1000.0).unwrap());
    assert!(service.is_repeat(&id("conf-second"), 1000.0).unwrap());
}

pub fn a_sighting_is_forgotten_past_its_lifetime(store: Arc<dyn SeenMessages>) {
    let service = DeduplicationService::new(store);
    assert!(!service.is_repeat(&id("conf-stale"), 1000.0).unwrap());
    assert!(!service
        .is_repeat(&id("conf-stale"), 1000.0 + 301.0)
        .unwrap());
}

pub fn a_sighting_still_counts_just_before_its_lifetime(store: Arc<dyn SeenMessages>) {
    let service = DeduplicationService::new(store);
    assert!(!service.is_repeat(&id("conf-fresh"), 1000.0).unwrap());
    assert!(service
        .is_repeat(&id("conf-fresh"), 1000.0 + 299.0)
        .unwrap());
}

pub fn different_identifiers_do_not_shadow_each_other(store: Arc<dyn SeenMessages>) {
    let service = DeduplicationService::new(store);
    assert!(!service.is_repeat(&id("conf-a"), 1000.0).unwrap());
    assert!(!service.is_repeat(&id("conf-b"), 1000.0).unwrap());
    assert!(service.is_repeat(&id("conf-a"), 1000.0).unwrap());
    assert!(service.is_repeat(&id("conf-b"), 1000.0).unwrap());
}

pub fn a_full_ledger_admits_the_newcomer_and_drops_the_oldest(store: Arc<dyn SeenMessages>) {
    let capacity = 8usize;
    let service = DeduplicationService::new(store);
    for n in 0..capacity {
        assert!(!service.is_repeat(&id(&format!("cap-{n}")), 1000.0).unwrap());
    }
    assert!(
        !service.is_repeat(&id("cap-newcomer"), 1000.0).unwrap(),
        "переполненная память обязана принять новый идентификатор, а не объявить его повтором"
    );
    assert!(
        service.is_repeat(&id("cap-newcomer"), 1000.0).unwrap(),
        "принятый идентификатор обязан помниться"
    );
    assert!(
        !service.is_repeat(&id("cap-0"), 1000.0).unwrap(),
        "вытесняется самый старый идентификатор"
    );
}
