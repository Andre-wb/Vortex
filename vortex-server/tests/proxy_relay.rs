mod support;

use support::{client, settings_for, start, stub_upstream};

#[tokio::test]
async fn an_unknown_path_is_carried_to_python_with_its_method_query_and_headers() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;

    let answered = client()
        .post(format!("{}/api/rooms?limit=10", node.edge))
        .header("x-carried", "carried-value")
        .body("тело")
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(answered.status(), 200);
    let reported: serde_json::Value =
        serde_json::from_str(&answered.text().await.expect("тело")).expect("json");
    assert_eq!(reported["method"], "POST");
    assert_eq!(reported["path"], "/api/rooms");
    assert_eq!(reported["query"], "limit=10");
    assert_eq!(reported["carried"], "carried-value");
}

#[tokio::test]
async fn a_dead_python_answers_bad_gateway_rather_than_hanging() {
    let node = start(settings_for("http://127.0.0.1:1")).await;

    let answered = client()
        .get(format!("{}/api/rooms", node.edge))
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(answered.status(), 502);
    let reported: serde_json::Value =
        serde_json::from_str(&answered.text().await.expect("тело")).expect("json");
    assert_eq!(reported["error"], "Bad gateway");
}

#[tokio::test]
async fn every_proxied_answer_carries_the_security_headers_of_the_node() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;

    let answered = client()
        .get(format!("{}/api/rooms", node.edge))
        .send()
        .await
        .expect("край отвечает");
    let headers = answered.headers();
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert!(headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("'nonce-"));
    assert!(headers.contains_key("x-request-id"));
}

#[tokio::test]
async fn a_request_identifier_sent_by_the_client_is_answered_verbatim() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;

    let answered = client()
        .get(format!("{}/api/rooms", node.edge))
        .header("x-request-id", "0123456789ab")
        .send()
        .await
        .expect("край отвечает");
    assert_eq!(
        answered.headers().get("x-request-id").unwrap(),
        "0123456789ab"
    );
}
