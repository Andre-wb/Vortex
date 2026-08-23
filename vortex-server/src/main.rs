use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;
use vortex_server::boot;
use vortex_server::router::build;
use vortex_server::settings::server::ServerSettings;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let settings = ServerSettings::from_environment();
    let Some(address) = settings.listen.resolve() else {
        tracing::error!(
            "адрес {}:{} не разобран — сервис не поднят",
            settings.listen.host(),
            settings.listen.port()
        );
        std::process::exit(1);
    };
    let upstream = settings.upstream.base().to_string();

    let state = match boot::assemble(settings).await {
        Ok(state) => state,
        Err(error) => {
            tracing::error!("сборка сервиса не удалась: {error}");
            std::process::exit(1);
        }
    };

    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("порт {address} не занят: {error}");
            std::process::exit(1);
        }
    };

    tracing::info!("axum слушает {address}, незнакомое уходит в {upstream}");
    let router = build::build(state);
    if let Err(error) = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        tracing::error!("сервис остановлен: {error}");
        std::process::exit(1);
    }
}
