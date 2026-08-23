mod support;

use vortex_routing::handler::decision::Handler;
use vortex_routing::route::name::RouteName;

use support::{client, settings_for, start, stub_upstream, LIVENESS_BODY};

fn route(value: &str) -> RouteName {
    RouteName::parse(value).unwrap()
}

#[tokio::test]
async fn an_unpointed_health_route_is_answered_by_python_itself() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;

    let answered = client()
        .get(format!("{}/health", node.edge))
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(answered.status(), 200);
    assert_eq!(answered.text().await.expect("тело"), LIVENESS_BODY);
}

#[tokio::test]
async fn a_health_route_pointed_at_rust_answers_the_same_field_set() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;
    node.state
        .flags
        .point(&route("health"), Handler::Rust)
        .await
        .expect("флаг ставится");

    let answered = client()
        .get(format!("{}/health", node.edge))
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(answered.status(), 200);
    let composed: serde_json::Value =
        serde_json::from_str(&answered.text().await.expect("тело")).expect("json");
    let reported: serde_json::Value = serde_json::from_str(LIVENESS_BODY).expect("json заглушки");
    assert_eq!(composed, reported);
}

#[tokio::test]
async fn a_dead_python_degrades_the_liveness_answer_instead_of_reporting_ok() {
    let node = start(settings_for("http://127.0.0.1:1")).await;
    node.state
        .flags
        .point(&route("health"), Handler::Rust)
        .await
        .expect("флаг ставится");

    let answered = client()
        .get(format!("{}/health", node.edge))
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(answered.status(), 503);
    let reported: serde_json::Value =
        serde_json::from_str(&answered.text().await.expect("тело")).expect("json");
    assert_eq!(reported["status"], "degraded");
    assert_eq!(reported["upstream"], "unreachable");
    assert!(reported.get("ws_connections").is_none());
}

#[tokio::test]
async fn the_readiness_route_pointed_at_rust_keeps_the_python_key_order() {
    let upstream = stub_upstream().await;
    let mut settings = settings_for(&upstream);
    let scratch = std::env::temp_dir().join("vortex-server-readiness");
    std::fs::create_dir_all(&scratch).expect("каталог создаётся");
    settings.paths = vortex_server::settings::paths::NodePaths::new(scratch.clone(), scratch);
    let node = start(settings).await;
    node.state
        .flags
        .point(&route("health-ready"), Handler::Rust)
        .await
        .expect("флаг ставится");

    let answered = client()
        .get(format!("{}/health/ready", node.edge))
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(answered.status(), 200);
    assert_eq!(
        answered.text().await.expect("тело"),
        r#"{"status":"ready","database":"ok","uploads_dir":"ok","keys_dir":"ok","background_tasks":"3/3 alive"}"#
    );
}
