mod support;

use vortex_storage::bot::inline::postgres::PgInlineResults;
use vortex_storage::bot::inline::results::InlineResults;
use vortex_storage::bot::scope::grants::ScopeGrants;
use vortex_storage::bot::scope::postgres::PgScopeGrants;
use vortex_storage::bot::webhook::postgres::reader::PgWebhookReader;
use vortex_storage::bot::webhook::postgres::writer::PgWebhookWriter;
use vortex_storage::bot::webhook::reader::WebhookReader;
use vortex_storage::bot::webhook::record::WebhookRecord;
use vortex_storage::bot::webhook::writer::WebhookWriter;
use vortex_storage::time::stamp::Stamp;

fn moment(seconds: i64, micros: u32) -> Stamp {
    Stamp::from_unix(seconds, micros).expect("отметка не собралась")
}

#[test]
fn a_webhook_returns_from_storage_exactly_as_it_went_in() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let owner = support::make_user(&handle, "webhook-roundtrip").await;
        let bot_id = support::make_bot(&handle, owner, "webhook-roundtrip").await;
        let writer = PgWebhookWriter::new(handle.clone());
        let reader = PgWebhookReader::new(handle.clone());

        let webhook = WebhookRecord {
            bot_id,
            url: "https://hooks.test/vortex".to_owned(),
            secret: "b".repeat(32),
            events: "[\"message\",\"reaction\"]".to_owned(),
            created_at: moment(1_785_834_930, 715_103),
        };
        writer.save(&webhook).await.expect("не записан");

        let found = reader
            .of_bot(bot_id)
            .await
            .expect("не прочитан")
            .expect("вебхука нет");
        assert_eq!(found, webhook);

        support::drop_user(&handle, owner).await;
    });
}

#[test]
fn saving_a_webhook_twice_replaces_it_instead_of_adding_a_second() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let owner = support::make_user(&handle, "webhook-replace").await;
        let bot_id = support::make_bot(&handle, owner, "webhook-replace").await;
        let writer = PgWebhookWriter::new(handle.clone());
        let reader = PgWebhookReader::new(handle.clone());

        for (url, at) in [
            ("https://first.test/hook", moment(1_785_834_930, 0)),
            ("https://second.test/hook", moment(1_785_834_999, 0)),
        ] {
            writer
                .save(&WebhookRecord {
                    bot_id,
                    url: url.to_owned(),
                    secret: "c".repeat(32),
                    events: "[]".to_owned(),
                    created_at: at,
                })
                .await
                .expect("не записан");
        }

        let found = reader
            .of_bot(bot_id)
            .await
            .expect("не прочитан")
            .expect("вебхука нет");
        assert_eq!(found.url, "https://second.test/hook");
        assert_eq!(found.created_at, moment(1_785_834_999, 0));

        support::drop_user(&handle, owner).await;
    });
}

#[test]
fn a_forgotten_webhook_stops_answering_and_says_it_was_there() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let owner = support::make_user(&handle, "webhook-forget").await;
        let bot_id = support::make_bot(&handle, owner, "webhook-forget").await;
        let writer = PgWebhookWriter::new(handle.clone());
        let reader = PgWebhookReader::new(handle.clone());

        writer
            .save(&WebhookRecord {
                bot_id,
                url: "https://hooks.test/gone".to_owned(),
                secret: "d".repeat(32),
                events: "[]".to_owned(),
                created_at: moment(1_785_834_930, 0),
            })
            .await
            .expect("не записан");

        assert!(writer.forget(bot_id).await.expect("не удалён"));
        assert!(!writer.forget(bot_id).await.expect("не удалён"));
        assert!(reader.of_bot(bot_id).await.expect("не прочитан").is_none());

        support::drop_user(&handle, owner).await;
    });
}

#[test]
fn granted_scopes_replace_each_other_and_never_double_up() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let owner = support::make_user(&handle, "scopes").await;
        let bot_id = support::make_bot(&handle, owner, "scopes").await;
        let grants = PgScopeGrants::new(handle.clone());

        assert!(grants
            .granted_to(bot_id)
            .await
            .expect("не прочитан")
            .is_empty());

        let first = vec!["messages.read".to_owned(), "messages.send".to_owned()];
        grants.replace(bot_id, &first).await.expect("не записан");
        assert_eq!(grants.granted_to(bot_id).await.expect("не прочитан"), first);

        let second = vec!["profile.read".to_owned()];
        grants.replace(bot_id, &second).await.expect("не записан");
        assert_eq!(
            grants.granted_to(bot_id).await.expect("не прочитан"),
            second
        );

        grants.replace(bot_id, &[]).await.expect("не записан");
        assert!(grants
            .granted_to(bot_id)
            .await
            .expect("не прочитан")
            .is_empty());

        support::drop_user(&handle, owner).await;
    });
}

#[test]
fn one_bot_never_answers_for_the_scopes_of_another() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let owner = support::make_user(&handle, "scopes-apart").await;
        let first = support::make_bot(&handle, owner, "scopes-apart").await;
        let second = support::make_bot(&handle, owner, "scopes-apart").await;
        let grants = PgScopeGrants::new(handle.clone());

        grants
            .replace(first, &["messages.read".to_owned()])
            .await
            .expect("не записан");
        assert!(grants
            .granted_to(second)
            .await
            .expect("не прочитан")
            .is_empty());

        support::drop_user(&handle, owner).await;
    });
}

#[test]
fn inline_answers_round_trip_and_the_ceiling_drops_the_oldest() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let owner = support::make_user(&handle, "inline").await;
        let bot_id = support::make_bot(&handle, owner, "inline").await;
        let results = PgInlineResults::new(handle.clone());

        assert!(results.of_bot(bot_id).await.expect("не прочитан").is_none());

        let answer = "[{\"id\":\"1\",\"title\":\"Привет\"}]";
        results
            .remember(bot_id, answer, moment(1_785_834_930, 0))
            .await
            .expect("не записан");
        assert_eq!(
            results.of_bot(bot_id).await.expect("не прочитан"),
            Some(answer.to_owned())
        );

        results
            .remember(bot_id, "[]", moment(1_785_834_999, 0))
            .await
            .expect("не записан");
        assert_eq!(
            results.of_bot(bot_id).await.expect("не прочитан"),
            Some("[]".to_owned())
        );

        results.keep_newest(0).await.expect("не подрезан");

        let mut bots = Vec::new();
        for index in 0..3 {
            let bot_id = support::make_bot(&handle, owner, "inline").await;
            results
                .remember(bot_id, "[]", moment(1_785_834_930 + index, 0))
                .await
                .expect("не записан");
            bots.push(bot_id);
        }

        assert_eq!(results.keep_newest(2).await.expect("не подрезан"), 1);
        assert!(results
            .of_bot(bots[0])
            .await
            .expect("не прочитан")
            .is_none());
        assert!(results
            .of_bot(bots[1])
            .await
            .expect("не прочитан")
            .is_some());
        assert!(results
            .of_bot(bots[2])
            .await
            .expect("не прочитан")
            .is_some());

        support::drop_user(&handle, owner).await;
    });
}
