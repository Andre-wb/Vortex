mod support;

use vortex_routing::handler::decision::Handler;
use vortex_routing::route::name::RouteName;

use support::{client, settings_for, start, stub_upstream};

fn route(value: &str) -> RouteName {
    RouteName::parse(value).unwrap()
}

#[tokio::test]
async fn an_unpointed_metrics_route_still_returns_the_python_exposition() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;

    let answered = client()
        .get(format!("{}/metrics", node.edge))
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(answered.text().await.expect("тело"), "python_exposition 1");
}

#[tokio::test]
async fn the_rust_exposition_never_repeats_a_python_family_name() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;
    node.state
        .flags
        .point(&route("metrics"), Handler::Rust)
        .await
        .expect("флаг ставится");

    client()
        .get(format!("{}/api/rooms/42", node.edge))
        .send()
        .await
        .expect("край отвечает");
    let exposition = client()
        .get(format!("{}/metrics", node.edge))
        .send()
        .await
        .expect("край отвечает")
        .text()
        .await
        .expect("тело");

    assert!(exposition.contains("vortex_edge_requests_total"));
    assert!(exposition.contains(r#"endpoint="/api/rooms/{id}""#));
    assert!(!exposition.contains("vortex_http_requests_total"));
}

#[tokio::test]
async fn a_loopback_scraper_is_admitted_even_when_a_token_is_configured() {
    let upstream = stub_upstream().await;
    let mut settings = settings_for(&upstream);
    settings.metrics_token = vortex_server::settings::metrics::MetricsToken::new("s3cret");
    let node = start(settings).await;
    node.state
        .flags
        .point(&route("metrics"), Handler::Rust)
        .await
        .expect("флаг ставится");

    let answered = client()
        .get(format!("{}/metrics", node.edge))
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(answered.status(), 200);
    assert!(answered
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/plain"));
}
