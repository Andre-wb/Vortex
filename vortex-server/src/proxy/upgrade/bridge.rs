use axum::body::Body;
use http::{Request, Response, StatusCode};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;

use crate::ports::upgrade_relay::UpgradeRelay;
use crate::proxy::refusal;
use crate::proxy::upgrade::outcome::UpgradeOutcome;
use crate::proxy::upgrade::pump::pump;

pub async fn bridge(relay: &dyn UpgradeRelay, mut request: Request<Body>) -> Response<Body> {
    let Some(client_upgrade) = request.extensions_mut().remove::<OnUpgrade>() else {
        return refusal::bad_gateway("клиент не предложил upgrade-соединение");
    };

    match relay.open(request).await {
        Ok(UpgradeOutcome::Switched { headers, socket }) => {
            tokio::spawn(async move {
                let mut upstream = socket;
                match client_upgrade.await {
                    Ok(client) => {
                        let mut client = TokioIo::new(client);
                        pump(&mut client, &mut upstream).await;
                    }
                    Err(error) => {
                        tracing::debug!("upgrade со стороны клиента не состоялся: {error}")
                    }
                }
            });
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            *response.headers_mut() = headers;
            response
        }
        Ok(UpgradeOutcome::Refused(response)) => response,
        Err(error) => refusal::bad_gateway(&error.to_string()),
    }
}
