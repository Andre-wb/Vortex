mod support;

use std::sync::Arc;

use vortex_storage::pool::handle::PgHandle;
use vortex_storage::prekey::one_time::key::OneTimeKey;
use vortex_storage::prekey::one_time::keys::OneTimeKeys;
use vortex_storage::prekey::one_time::postgres::classic::PgClassicKeys;
use vortex_storage::prekey::one_time::postgres::kyber::PgKyberKeys;
use vortex_storage::time::stamp::Stamp;

fn moment() -> Stamp {
    Stamp::from_unix(1_785_834_930, 715_103).expect("отметка не собралась")
}

fn pools(handle: &PgHandle) -> Vec<(&'static str, Arc<dyn OneTimeKeys>, usize)> {
    vec![
        (
            "классический",
            Arc::new(PgClassicKeys::new(handle.clone())) as Arc<dyn OneTimeKeys>,
            32,
        ),
        (
            "kyber",
            Arc::new(PgKyberKeys::new(handle.clone())) as Arc<dyn OneTimeKeys>,
            1184,
        ),
    ]
}

fn batch(count: i64, width: usize) -> Vec<OneTimeKey> {
    (0..count)
        .map(|index| OneTimeKey::new(index, vec![(index % 256) as u8; width]))
        .collect()
}

#[test]
fn a_pool_hands_out_its_keys_in_publication_order_and_only_once() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        for (name, pool, width) in pools(&handle) {
            let user_id = support::make_user(&handle, "one-time-order").await;
            let keys = batch(3, width);
            assert_eq!(
                pool.add_many(user_id, None, &keys, moment())
                    .await
                    .expect("пачка не записана"),
                3,
                "{name}"
            );
            assert_eq!(
                pool.available(user_id, None).await.expect("не посчитан"),
                3,
                "{name}"
            );

            for expected in &keys {
                let taken = pool
                    .take_one(user_id, None)
                    .await
                    .expect("не выдан")
                    .expect("ключа нет");
                assert_eq!(&taken, expected, "{name}");
            }

            assert_eq!(
                pool.take_one(user_id, None).await.expect("не выдан"),
                None,
                "{name}"
            );
            assert_eq!(
                pool.available(user_id, None).await.expect("не посчитан"),
                0,
                "{name}"
            );
            support::drop_user(&handle, user_id).await;
        }
    });
}

#[test]
fn an_empty_batch_touches_nothing() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        for (name, pool, _) in pools(&handle) {
            let user_id = support::make_user(&handle, "one-time-empty").await;
            assert_eq!(
                pool.add_many(user_id, None, &[], moment())
                    .await
                    .expect("пустая пачка не прошла"),
                0,
                "{name}"
            );
            assert_eq!(
                pool.available(user_id, None).await.expect("не посчитан"),
                0,
                "{name}"
            );
            support::drop_user(&handle, user_id).await;
        }
    });
}

#[test]
fn the_pools_of_two_devices_are_drawn_from_separately() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        for (name, pool, width) in pools(&handle) {
            let user_id = support::make_user(&handle, "one-time-devices").await;
            let device_id = support::make_device(&handle, user_id, &"f".repeat(32)).await;

            pool.add_many(user_id, None, &batch(1, width), moment())
                .await
                .expect("пачка не записана");
            pool.add_many(user_id, Some(device_id), &batch(2, width), moment())
                .await
                .expect("пачка не записана");

            assert_eq!(
                pool.available(user_id, None).await.expect("не посчитан"),
                1,
                "{name}"
            );
            assert_eq!(
                pool.available(user_id, Some(device_id))
                    .await
                    .expect("не посчитан"),
                2,
                "{name}"
            );

            pool.take_one(user_id, Some(device_id))
                .await
                .expect("не выдан")
                .expect("ключа нет");
            assert_eq!(
                pool.available(user_id, None).await.expect("не посчитан"),
                1,
                "{name}"
            );

            support::drop_user(&handle, user_id).await;
        }
    });
}

#[test]
fn two_parallel_claims_never_hand_out_the_same_key() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("рантайм не поднялся");
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        for (name, pool, width) in pools(&handle) {
            let user_id = support::make_user(&handle, "one-time-race").await;
            let count = 20_i64;
            pool.add_many(user_id, None, &batch(count, width), moment())
                .await
                .expect("пачка не записана");

            let mut claims = Vec::new();
            for _ in 0..count * 2 {
                let pool = Arc::clone(&pool);
                claims.push(tokio::spawn(async move {
                    pool.take_one(user_id, None).await.expect("не выдан")
                }));
            }

            let mut handed = Vec::new();
            for claim in claims {
                if let Some(key) = claim.await.expect("задача упала") {
                    handed.push(key.key_id);
                }
            }
            handed.sort_unstable();
            let issued = handed.len();
            handed.dedup();
            assert_eq!(handed.len(), issued, "{name}: ключ выдан дважды");
            assert_eq!(issued, count as usize, "{name}");

            support::drop_user(&handle, user_id).await;
        }
    });
}
