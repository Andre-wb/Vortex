#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use vortex_storage::config::dsn::PgConfig;
use vortex_storage::pool::handle::PgHandle;

pub const DEFAULT_TEST_URL: &str = "postgres://localhost:5432/vortex_sqlx";

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn unique_name(suite: &str) -> String {
    let index = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    format!("vortex-test-{suite}-{pid}-{index}")
}

pub async fn handle() -> Option<PgHandle> {
    let required = std::env::var("VORTEX_TEST_PG_URL").ok();
    let url = required
        .clone()
        .unwrap_or_else(|| DEFAULT_TEST_URL.to_string());
    let config = PgConfig::new(url.clone()).pool_size(4);

    match PgHandle::connect(&config).await {
        Ok(handle) => Some(handle),
        Err(error) if required.is_some() => {
            panic!("VORTEX_TEST_PG_URL={url} задан, но Postgres недоступен: {error}")
        }
        Err(error) => {
            eprintln!("Postgres по адресу {url} недоступен ({error}) — проверка пропущена");
            None
        }
    }
}

pub async fn make_user(handle: &PgHandle, suite: &str) -> i64 {
    let username = unique_name(suite);
    let row = sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash)
        VALUES ($1, 'x')
        RETURNING id
        "#,
        username
    )
    .fetch_one(handle.pool())
    .await
    .expect("пользователь не создан");
    i64::from(row.id)
}

pub async fn drop_user(handle: &PgHandle, user_id: i64) {
    sqlx::query!(
        "DELETE FROM users WHERE id = $1",
        i32::try_from(user_id).expect("идентификатор не помещается в колонку")
    )
    .execute(handle.pool())
    .await
    .expect("пользователь не удалён");
}

pub async fn make_device(handle: &PgHandle, user_id: i64, client_device_id: &str) -> i64 {
    let row = sqlx::query!(
        r#"
        INSERT INTO user_devices (user_id, device_name, client_device_id)
        VALUES ($1, 'test', $2)
        RETURNING id
        "#,
        i32::try_from(user_id).expect("идентификатор не помещается в колонку"),
        client_device_id
    )
    .fetch_one(handle.pool())
    .await
    .expect("устройство не создано");
    i64::from(row.id)
}

pub async fn make_bot(handle: &PgHandle, owner_id: i64, suite: &str) -> i64 {
    let account = make_user(handle, suite).await;
    let row = sqlx::query!(
        r#"
        INSERT INTO bots (user_id, owner_id, api_token, name)
        VALUES ($1, $2, $3, 'test-bot')
        RETURNING id
        "#,
        i32::try_from(account).expect("идентификатор не помещается в колонку"),
        i32::try_from(owner_id).expect("идентификатор не помещается в колонку"),
        unique_name(suite)
    )
    .fetch_one(handle.pool())
    .await
    .expect("бот не создан");
    i64::from(row.id)
}

pub fn unique_code() -> String {
    let index = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    format!("{pid:x}{index:x}")
}

pub async fn make_room(handle: &PgHandle, creator_id: i64, _suite: &str) -> i64 {
    let row = sqlx::query!(
        r#"
        INSERT INTO rooms (name, invite_code, creator_id)
        VALUES ('test-room', $1, $2)
        RETURNING id
        "#,
        unique_code(),
        i32::try_from(creator_id).expect("идентификатор не помещается в колонку")
    )
    .fetch_one(handle.pool())
    .await
    .expect("комната не создана");
    i64::from(row.id)
}

pub async fn drop_room(handle: &PgHandle, room_id: i64) {
    sqlx::query!(
        "DELETE FROM rooms WHERE id = $1",
        i32::try_from(room_id).expect("идентификатор не помещается в колонку")
    )
    .execute(handle.pool())
    .await
    .expect("комната не удалена");
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("рантайм не поднялся")
}
