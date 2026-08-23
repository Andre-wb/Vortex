use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use vortex_auth::account::user_id::UserId;

use crate::identity::person::Person;
use crate::ports::voice_presence::VoicePresence;
use crate::testing::{blink, until, BASE, BLINK, BLINK_MILLIS};
use crate::voice::participant::Participant;
use crate::voice::patch::MutePatch;
use crate::voice::record::Presence;
use vortex_core::room::room_id::RoomId;

pub type VoicePresenceFactory = dyn Fn() -> Arc<dyn VoicePresence>;

fn room() -> RoomId {
    RoomId::of(1).expect("номер комнаты положителен")
}

fn user(value: i64) -> UserId {
    UserId::of(value).expect("номер учётной записи положителен")
}

fn presence(user_id: i64, joined_at: &str, until: f64) -> Presence {
    let person = Person::of(user_id, "member", None, None, None);
    Presence::new(
        Participant {
            user_id: person.user_id,
            username: person.username,
            display_name: person.display_name,
            avatar_emoji: person.avatar_emoji,
            avatar_url: person.avatar_url,
            joined_at: joined_at.to_owned(),
            is_muted: false,
            is_video: false,
        },
        until,
    )
}

pub fn check_all(make: &VoicePresenceFactory) {
    a_channel_nobody_joined_is_empty(make);
    a_joined_participant_is_listed(make);
    joining_twice_seats_the_participant_once(make);
    leaving_gives_back_who_left_and_only_once(make);
    the_channel_lists_participants_in_the_order_they_joined(make);
    amending_flips_the_flags_of_one_participant(make);
    a_participant_nobody_renews_drops_off(make);
    renewing_keeps_a_silent_participant(make);
}

pub fn a_channel_nobody_joined_is_empty(make: &VoicePresenceFactory) {
    let store = make();
    assert!(store.list(room(), BASE).unwrap().is_empty());
    assert_eq!(store.find(room(), user(7), BASE).unwrap(), None);
    assert_eq!(store.leave(room(), user(7), BASE).unwrap(), None);
    assert!(!store.renew(room(), user(7), until(BASE), BASE).unwrap());
}

pub fn a_joined_participant_is_listed(make: &VoicePresenceFactory) {
    let store = make();
    let seat = presence(7, "2026-08-04T09:15:30+00:00", until(BASE));
    assert!(!store.join(room(), &seat, BASE).unwrap().already_in());

    assert_eq!(store.list(room(), BASE).unwrap().len(), 1);
    assert_eq!(
        store.find(room(), user(7), BASE).unwrap().unwrap().user_id,
        7
    );
}

pub fn joining_twice_seats_the_participant_once(make: &VoicePresenceFactory) {
    let store = make();
    let seat = presence(7, "2026-08-04T09:15:30+00:00", until(BASE));
    store.join(room(), &seat, BASE).unwrap();

    let again = presence(7, "2026-08-04T09:20:00+00:00", until(BASE));
    let joined = store.join(room(), &again, BASE).unwrap();
    assert!(joined.already_in());
    assert_eq!(joined.participant().joined_at, "2026-08-04T09:15:30+00:00");
    assert_eq!(store.list(room(), BASE).unwrap().len(), 1);
}

pub fn leaving_gives_back_who_left_and_only_once(make: &VoicePresenceFactory) {
    let store = make();
    store
        .join(
            room(),
            &presence(7, "2026-08-04T09:15:30+00:00", until(BASE)),
            BASE,
        )
        .unwrap();

    assert_eq!(
        store.leave(room(), user(7), BASE).unwrap().unwrap().user_id,
        7
    );
    assert_eq!(store.leave(room(), user(7), BASE).unwrap(), None);
    assert!(store.list(room(), BASE).unwrap().is_empty());
}

pub fn the_channel_lists_participants_in_the_order_they_joined(make: &VoicePresenceFactory) {
    let store = make();
    store
        .join(
            room(),
            &presence(8, "2026-08-04T09:15:30+00:00", until(BASE)),
            BASE,
        )
        .unwrap();
    store
        .join(
            room(),
            &presence(7, "2026-08-04T09:16:30+00:00", until(BASE)),
            BASE,
        )
        .unwrap();

    let listed = store.list(room(), BASE).unwrap();
    assert_eq!(listed[0].user_id, 8);
    assert_eq!(listed[1].user_id, 7);
}

pub fn amending_flips_the_flags_of_one_participant(make: &VoicePresenceFactory) {
    let store = make();
    store
        .join(
            room(),
            &presence(7, "2026-08-04T09:15:30+00:00", until(BASE)),
            BASE,
        )
        .unwrap();
    store
        .join(
            room(),
            &presence(8, "2026-08-04T09:16:30+00:00", until(BASE)),
            BASE,
        )
        .unwrap();

    let amended = store
        .amend(
            room(),
            user(7),
            MutePatch::new(None, Some(true)),
            until(BASE),
            BASE,
        )
        .unwrap()
        .unwrap();
    assert!(amended.is_muted);
    assert!(amended.is_video);
    assert!(!store.find(room(), user(8), BASE).unwrap().unwrap().is_muted);
    assert_eq!(
        store
            .amend(room(), user(9), MutePatch::default(), until(BASE), BASE)
            .unwrap(),
        None
    );
}

pub fn a_participant_nobody_renews_drops_off(make: &VoicePresenceFactory) {
    let store = make();
    store
        .join(
            room(),
            &presence(7, "2026-08-04T09:15:30+00:00", blink(BASE)),
            BASE,
        )
        .unwrap();
    sleep(Duration::from_millis(BLINK_MILLIS));

    assert!(store.list(room(), BASE + BLINK).unwrap().is_empty());
    assert_eq!(store.find(room(), user(7), BASE + BLINK).unwrap(), None);
}

pub fn renewing_keeps_a_silent_participant(make: &VoicePresenceFactory) {
    let store = make();
    store
        .join(
            room(),
            &presence(7, "2026-08-04T09:15:30+00:00", blink(BASE)),
            BASE,
        )
        .unwrap();
    assert!(store.renew(room(), user(7), until(BASE), BASE).unwrap());
    sleep(Duration::from_millis(BLINK_MILLIS));

    assert_eq!(store.list(room(), BASE + BLINK).unwrap().len(), 1);
}
