mod support;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use support::{settings_for, start, stub_upstream};

#[tokio::test]
async fn a_websocket_upgrade_is_carried_through_the_edge_to_python() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;
    let address = node.edge.replace("http://", "ws://");

    let (mut socket, answered) = tokio_tungstenite::connect_async(format!("{address}/ws/echo"))
        .await
        .expect("upgrade проходит через край");
    assert_eq!(answered.status(), 101);

    socket
        .send(Message::Text("привет".into()))
        .await
        .expect("кадр уходит");
    let echoed = socket
        .next()
        .await
        .expect("кадр приходит")
        .expect("кадр цел");
    assert_eq!(echoed, Message::Text("эхо: привет".into()));
}

#[tokio::test]
async fn a_upgrade_to_a_path_python_does_not_serve_is_answered_not_switched() {
    let upstream = stub_upstream().await;
    let node = start(settings_for(&upstream)).await;
    let address = node.edge.replace("http://", "ws://");

    let outcome = tokio_tungstenite::connect_async(format!("{address}/ws/нет-такого")).await;
    assert!(outcome.is_err());
}
