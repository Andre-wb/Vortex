use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use vortex_proto::message::frame::edit::EditFrame;
use vortex_proto::message::frame::incoming::IncomingFrame;
use vortex_proto::message::frame::send::SendFrame;
use vortex_proto::message::relay::sender::Sender;
use vortex_proto::message::relay::sent::{SentMessage, SentMessageDraft};
use vortex_proto::message::time::client_stamp::ClientStamp;
use vortex_proto::room::settings::patch::RoomPatch;
use vortex_proto::room::settings::request::RoomPatchRequest;
use vortex_proto::room::view::{RoomRow, RoomView};
use vortex_proto::wrap::envelope::WrappedKey;
use vortex_proto::wrap::render::WrapView;
use vortex_proto::wrap::request::WrapRequest;

const NOW: i64 = 1_785_834_930_000_000;

fn ciphertext(bytes: usize) -> String {
    "ab".repeat(bytes)
}

fn plain_frame(payload: usize) -> String {
    format!(
        r#"{{"action":"message","ciphertext":"{}","msg_id":"c-1"}}"#,
        ciphertext(payload)
    )
}

fn rich_frame(payload: usize) -> String {
    format!(
        r#"{{"action":"message","ciphertext":"{}","msg_id":"c-1","enc_v":2,"reply_to_id":12,"reply_quote":"hi","client_ts":"2026-08-04T09:15:30.789Z","mentioned_usernames":["alice","bob","carol"]}}"#,
        ciphertext(payload)
    )
}

fn message(criterion: &mut Criterion) {
    for payload in [64usize, 1024, 16384] {
        let plain = plain_frame(payload);
        criterion.bench_function(&format!("send/plain/{payload}"), |bencher| {
            bencher.iter(|| {
                let frame = IncomingFrame::from_json(black_box(&plain)).unwrap();
                black_box(SendFrame::read(&frame, NOW).unwrap());
            })
        });
    }

    let rich = rich_frame(1024);
    criterion.bench_function("send/rich/1024", |bencher| {
        bencher.iter(|| {
            let frame = IncomingFrame::from_json(black_box(&rich)).unwrap();
            black_box(SendFrame::read(&frame, NOW).unwrap());
        })
    });

    let refused = format!(r#"{{"ciphertext":"{}"}}"#, ciphertext(10));
    criterion.bench_function("send/refused", |bencher| {
        bencher.iter(|| {
            let frame = IncomingFrame::from_json(black_box(&refused)).unwrap();
            black_box(SendFrame::read(&frame, NOW).unwrap_err());
        })
    });

    let edit = format!(
        r#"{{"msg_id":9,"ciphertext":"{}","enc_v":1}}"#,
        ciphertext(1024)
    );
    criterion.bench_function("edit/1024", |bencher| {
        bencher.iter(|| {
            let frame = IncomingFrame::from_json(black_box(&edit)).unwrap();
            black_box(EditFrame::read(&frame).unwrap());
        })
    });

    criterion.bench_function("client_stamp", |bencher| {
        bencher.iter(|| black_box(ClientStamp::within_window("2026-08-04T09:15:30.789Z", NOW)))
    });

    let hex = ciphertext(1024);
    let digest = "aa".repeat(32);
    criterion.bench_function("relay/sent", |bencher| {
        bencher.iter(|| {
            black_box(SentMessage::render(SentMessageDraft {
                msg_id: 42,
                client_msg_id: "c-1",
                sender: Sender::named("alice", Some("Alice")),
                ciphertext: black_box(&hex),
                hash: &digest,
                enc_v: Some(2),
                reply_to_id: Some(7),
                reply_quote: Some("hi"),
                forwarded_from: None,
                expires_at: Some(NOW / 1_000_000 + 60),
                created_at: NOW / 1_000_000,
            }))
        })
    });
}

fn wrapped_key(criterion: &mut Criterion) {
    let classical = format!(
        r#"{{"ephemeral_pub":"{}","ciphertext":"{}"}}"#,
        "1a".repeat(32),
        "2b".repeat(60)
    );
    let hybrid = format!(
        r#"{{"hybrid":true,"x25519_ephemeral_pub":"{}","kyber_ciphertext":"{}","ciphertext":"{}"}}"#,
        "1a".repeat(32),
        "3c".repeat(1088),
        "2b".repeat(60)
    );

    criterion.bench_function("wrap/classical", |bencher| {
        bencher.iter(|| {
            let request = WrapRequest::from_json(black_box(&classical)).unwrap();
            let parsed = WrappedKey::parse(&request).unwrap();
            black_box(WrapView::of(&parsed));
        })
    });

    criterion.bench_function("wrap/hybrid", |bencher| {
        bencher.iter(|| {
            let request = WrapRequest::from_json(black_box(&hybrid)).unwrap();
            let parsed = WrappedKey::parse(&request).unwrap();
            black_box(WrapView::of(&parsed));
        })
    });
}

fn room(criterion: &mut Criterion) {
    let patch = r#"{"name":"General","description":"a room","slow_mode_seconds":15,"antispam_config":"{\"threshold\":10,\"action\":\"mute\"}","reactions_type":"all"}"#;
    criterion.bench_function("room/settings", |bencher| {
        bencher.iter(|| {
            let request = RoomPatchRequest::from_json(black_box(patch)).unwrap();
            black_box(RoomPatch::read(&request).unwrap());
        })
    });

    criterion.bench_function("room/view", |bencher| {
        bencher.iter(|| {
            black_box(RoomView::render(RoomRow {
                id: 7,
                name: "General",
                description: Some("a room"),
                is_private: Some(false),
                is_channel: Some(false),
                is_voice: Some(false),
                invite_code: Some("abcd1234"),
                member_count: 3,
                online_count: 1,
                avatar_emoji: None,
                avatar_url: None,
                auto_delete_seconds: None,
                slow_mode_seconds: Some(15),
                antispam_enabled: Some(true),
                antispam_config: None,
                creator_id: Some(2),
                created_at: (NOW / 1_000_000, 789_012),
                theme_json: None,
                discussion_enabled: None,
                reactions_type: None,
                allowed_reactions: None,
                admin_signatures: None,
                copy_protection: None,
                silent_default: None,
                join_approval: None,
                hashtags_enabled: None,
                replication_mode: None,
                is_dm: None,
            }))
        })
    });
}

criterion_group!(benches, message, wrapped_key, room);
criterion_main!(benches);
