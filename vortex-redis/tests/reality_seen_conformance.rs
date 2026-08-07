mod support;

use std::sync::Arc;

use vortex_redis::transport::seen_envelopes::RedisSeenEnvelopes;
use vortex_transport::ports::seen_envelopes::SeenEnvelopes;
use vortex_transport::reality::replay::memory_seen::MemorySeenEnvelopes;

fn check_all(make: &dyn Fn(usize) -> Arc<dyn SeenEnvelopes>) {
    let seen = make(100);
    assert!(seen.remember(b"envelope", 100));
    assert!(!seen.remember(b"envelope", 100));
    assert_eq!(seen.len(), 1);

    let seen = make(100);
    seen.remember(b"envelope", 100);
    seen.prune(101);
    assert!(seen.is_empty());
    assert!(seen.remember(b"envelope", 200));

    let seen = make(100);
    seen.remember(b"envelope", 100);
    seen.prune(100);
    assert_eq!(
        seen.len(),
        1,
        "конверт живёт до последней принимаемой секунды"
    );

    let seen = make(1);
    assert!(seen.remember(b"first", 100));
    assert!(
        !seen.remember(b"second", 100),
        "полный кэш отказывает, а не вытесняет"
    );
}

#[test]
fn the_in_memory_replay_cache_satisfies_the_port_contract() {
    let make = |capacity: usize| -> Arc<dyn SeenEnvelopes> {
        Arc::new(MemorySeenEnvelopes::with_capacity(capacity))
    };
    check_all(&make);
}

#[test]
fn the_redis_replay_cache_satisfies_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("seen-probe")).is_none() {
        eprintln!("Redis недоступен — проверка кэша повторов пропущена");
        return;
    }
    let make = |capacity: usize| -> Arc<dyn SeenEnvelopes> {
        let prefix = support::unique_prefix("seen");
        Arc::new(RedisSeenEnvelopes::with_capacity(
            support::backbone(&prefix).unwrap(),
            capacity,
        ))
    };
    check_all(&make);
}
