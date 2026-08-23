mod support;

use vortex_storage::push::unified::directory::UnifiedPushDirectory;
use vortex_storage::push::unified::postgres::PgUnifiedPushDirectory;
use vortex_storage::push::unified::subscription::UnifiedSubscription;
use vortex_storage::time::stamp::Stamp;

fn moment(seconds: i64, micros: u32) -> Stamp {
    Stamp::from_unix(seconds, micros).expect("отметка не собралась")
}

fn sample(user_id: i64, endpoint: &str) -> UnifiedSubscription {
    UnifiedSubscription {
        user_id,
        endpoint: endpoint.to_owned(),
        app_id: "org.vortex.messenger".to_owned(),
        created_at: moment(1_785_834_930, 715_103),
        failures: 0,
        active: true,
    }
}

#[test]
fn a_subscription_returns_from_storage_exactly_as_it_went_in() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "up-roundtrip").await;
        let directory = PgUnifiedPushDirectory::new(handle.clone());

        let subscription = sample(user_id, "https://ntfy.test/vortex-1");
        directory.register(&subscription).await.expect("не записан");

        let found = directory.of_user(user_id).await.expect("не прочитан");
        assert_eq!(found, vec![subscription]);

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn registering_one_endpoint_twice_keeps_a_single_subscription() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "up-replace").await;
        let directory = PgUnifiedPushDirectory::new(handle.clone());
        let endpoint = "https://ntfy.test/vortex-2";

        directory
            .register(&sample(user_id, endpoint))
            .await
            .expect("не записан");
        let mut again = sample(user_id, endpoint);
        again.app_id = "org.vortex.fork".to_owned();
        directory.register(&again).await.expect("не записан");

        let found = directory.of_user(user_id).await.expect("не прочитан");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].app_id, "org.vortex.fork");

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn two_endpoints_of_one_account_both_survive() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "up-two").await;
        let directory = PgUnifiedPushDirectory::new(handle.clone());

        for endpoint in ["https://ntfy.test/a", "https://ntfy.test/b"] {
            directory
                .register(&sample(user_id, endpoint))
                .await
                .expect("не записан");
        }

        assert_eq!(
            directory.of_user(user_id).await.expect("не прочитан").len(),
            2
        );

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn an_unregistered_endpoint_stops_answering_and_says_it_was_there() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "up-unregister").await;
        let directory = PgUnifiedPushDirectory::new(handle.clone());
        let endpoint = "https://ntfy.test/gone";

        directory
            .register(&sample(user_id, endpoint))
            .await
            .expect("не записан");
        assert!(directory
            .unregister(user_id, endpoint)
            .await
            .expect("не удалён"));
        assert!(!directory
            .unregister(user_id, endpoint)
            .await
            .expect("не удалён"));
        assert!(directory
            .of_user(user_id)
            .await
            .expect("не прочитан")
            .is_empty());

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn a_recorded_run_of_failures_disables_the_subscription() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "up-failures").await;
        let directory = PgUnifiedPushDirectory::new(handle.clone());
        let endpoint = "https://ntfy.test/failing";

        directory
            .register(&sample(user_id, endpoint))
            .await
            .expect("не записан");
        directory
            .record_delivery(user_id, endpoint, 15, false)
            .await
            .expect("не записан");

        let found = directory.of_user(user_id).await.expect("не прочитан");
        assert_eq!((found[0].failures, found[0].active), (15, false));

        support::drop_user(&handle, user_id).await;
    });
}
