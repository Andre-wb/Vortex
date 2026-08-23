mod support;

use vortex_storage::draft::drafts::Drafts;
use vortex_storage::draft::postgres::PgDrafts;
use vortex_storage::draft::record::DraftRecord;
use vortex_storage::time::stamp::Stamp;

fn moment(seconds: i64, micros: u32) -> Stamp {
    Stamp::from_unix(seconds, micros).expect("отметка не собралась")
}

#[test]
fn a_draft_returns_from_storage_exactly_as_it_went_in() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "draft-roundtrip").await;
        let room_id = support::make_room(&handle, user_id, "draft-roundtrip").await;
        let drafts = PgDrafts::new(handle.clone());

        assert!(drafts
            .of_member(user_id, room_id)
            .await
            .expect("не прочитан")
            .is_none());

        let draft = DraftRecord {
            user_id,
            room_id,
            text: "недописанное сообщение".to_owned(),
            updated_at: moment(1_785_834_930, 715_103),
        };
        drafts.save(&draft).await.expect("не записан");

        let found = drafts
            .of_member(user_id, room_id)
            .await
            .expect("не прочитан")
            .expect("черновика нет");
        assert_eq!(found, draft);

        support::drop_room(&handle, room_id).await;
        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn saving_a_draft_twice_replaces_its_text() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "draft-replace").await;
        let room_id = support::make_room(&handle, user_id, "draft-replace").await;
        let drafts = PgDrafts::new(handle.clone());

        for (text, at) in [
            ("первый", moment(1_785_834_930, 0)),
            ("второй", moment(1_785_834_999, 0)),
        ] {
            drafts
                .save(&DraftRecord {
                    user_id,
                    room_id,
                    text: text.to_owned(),
                    updated_at: at,
                })
                .await
                .expect("не записан");
        }

        let found = drafts
            .of_member(user_id, room_id)
            .await
            .expect("не прочитан")
            .expect("черновика нет");
        assert_eq!(found.text, "второй");
        assert_eq!(found.updated_at, moment(1_785_834_999, 0));

        support::drop_room(&handle, room_id).await;
        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn one_room_never_answers_for_the_draft_of_another() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "draft-apart").await;
        let first = support::make_room(&handle, user_id, "draft-apart").await;
        let second = support::make_room(&handle, user_id, "draft-apart").await;
        let drafts = PgDrafts::new(handle.clone());

        drafts
            .save(&DraftRecord {
                user_id,
                room_id: first,
                text: "только здесь".to_owned(),
                updated_at: moment(1_785_834_930, 0),
            })
            .await
            .expect("не записан");

        assert!(drafts
            .of_member(user_id, second)
            .await
            .expect("не прочитан")
            .is_none());

        support::drop_room(&handle, first).await;
        support::drop_room(&handle, second).await;
        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn a_cleared_draft_stops_answering_and_says_it_was_there() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "draft-clear").await;
        let room_id = support::make_room(&handle, user_id, "draft-clear").await;
        let drafts = PgDrafts::new(handle.clone());

        drafts
            .save(&DraftRecord {
                user_id,
                room_id,
                text: "стереть".to_owned(),
                updated_at: moment(1_785_834_930, 0),
            })
            .await
            .expect("не записан");

        assert!(drafts.clear(user_id, room_id).await.expect("не удалён"));
        assert!(!drafts.clear(user_id, room_id).await.expect("не удалён"));
        assert!(drafts
            .of_member(user_id, room_id)
            .await
            .expect("не прочитан")
            .is_none());

        support::drop_room(&handle, room_id).await;
        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn a_draft_untouched_past_the_cutoff_is_forgotten_and_a_fresh_one_is_not() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "draft-stale").await;
        let stale_room = support::make_room(&handle, user_id, "draft-stale").await;
        let fresh_room = support::make_room(&handle, user_id, "draft-stale").await;
        let drafts = PgDrafts::new(handle.clone());

        drafts
            .save(&DraftRecord {
                user_id,
                room_id: stale_room,
                text: "старое".to_owned(),
                updated_at: moment(1_000_000_000, 0),
            })
            .await
            .expect("не записан");
        drafts
            .save(&DraftRecord {
                user_id,
                room_id: fresh_room,
                text: "свежее".to_owned(),
                updated_at: moment(1_785_834_930, 0),
            })
            .await
            .expect("не записан");

        let removed = drafts
            .forget_untouched_since(moment(1_700_000_000, 0))
            .await
            .expect("не подчищен");
        assert!(removed >= 1);
        assert!(drafts
            .of_member(user_id, stale_room)
            .await
            .expect("не прочитан")
            .is_none());
        assert!(drafts
            .of_member(user_id, fresh_room)
            .await
            .expect("не прочитан")
            .is_some());

        support::drop_room(&handle, stale_room).await;
        support::drop_room(&handle, fresh_room).await;
        support::drop_user(&handle, user_id).await;
    });
}
