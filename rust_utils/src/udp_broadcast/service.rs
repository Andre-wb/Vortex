use crate::registry::shared as registry;
use crate::udp_broadcast::{DiscoverySettings, Shared};
use std::error::Error;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time;
use vortex_net::net::{is_loopback, subnet_broadcast};
use vortex_net::random::OsRandom;
use vortex_net::stealth;
use vortex_net::wire;

const LOCAL_IP_PROBES: [&str; 4] = [
    "192.168.1.1:80",
    "10.0.0.1:80",
    "172.16.0.1:80",
    "8.8.8.8:80",
];
const FALLBACK_IP: &str = "127.0.0.1";
const RECV_BUFFER: usize = 1024;

pub async fn run_discovery(
    settings: DiscoverySettings,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let send_socket = UdpSocket::bind("0.0.0.0:0").await?;
    send_socket.set_broadcast(true)?;

    let recv_socket = UdpSocket::bind(("0.0.0.0", settings.udp_port)).await?;

    registry::set_own_address(detect_local_ip());

    let shared = Arc::new(Shared { settings });

    let sender = tokio::spawn(run_sender(send_socket, shared.clone()));
    let receiver = tokio::spawn(run_receiver(recv_socket, shared));

    let _ = tokio::join!(sender, receiver);
    Ok(())
}

async fn run_sender(socket: UdpSocket, shared: Arc<Shared>) {
    let settings = &shared.settings;
    let random = OsRandom::new();
    let global_target = format!("255.255.255.255:{}", settings.udp_port);
    let mut ticker = time::interval(settings.interval);

    loop {
        ticker.tick().await;

        let detected = detect_local_ip();
        if !is_loopback(&detected) {
            registry::set_own_address(detected);
        }
        let own_ip = registry::own_address();

        let mut payload = wire::encode(
            &settings.name,
            settings.signaling_port,
            settings.node_pubkey_hex.as_deref(),
        );
        if settings.stealth {
            payload = stealth::seal_with(&payload, &random, &settings.network_key);
        }

        let subnet_target = format!("{}:{}", subnet_broadcast(&own_ip), settings.udp_port);
        let _ = socket.send_to(&payload, &subnet_target).await;
        let _ = socket.send_to(&payload, &global_target).await;
    }
}

async fn run_receiver(socket: UdpSocket, shared: Arc<Shared>) {
    let settings = &shared.settings;
    let mut buffer = vec![0u8; RECV_BUFFER];

    loop {
        let (size, source) = match socket.recv_from(&mut buffer).await {
            Ok(value) => value,
            Err(error) => {
                log::debug!("udp discovery: ошибка приёма: {}", error);
                continue;
            }
        };

        let source_ip = source.ip().to_string();
        if source_ip == registry::own_address() || is_loopback(&source_ip) {
            continue;
        }

        let raw: &[u8] = &buffer[..size];
        let decrypted: Vec<u8>;
        let frame: &[u8] = if settings.stealth {
            if let Some(opened) = stealth::open(raw, &settings.network_key) {
                decrypted = opened;
                &decrypted
            } else {
                raw
            }
        } else {
            raw
        };

        if let Some(decoded) = wire::decode(frame, &source_ip, settings.signaling_port) {
            let heard = registry::registry().heard(
                &source_ip,
                &decoded.name,
                decoded.port,
                decoded.pubkey.as_deref(),
                registry::now(),
            );
            match heard {
                Err(refusal) => log::debug!("udp discovery: узел отклонён: {}", refusal),
                Ok(Err(error)) => log::warn!("udp discovery: реестр недоступен: {}", error),
                Ok(Ok(_)) => {}
            }
        }
    }
}

fn detect_local_ip() -> String {
    for probe in LOCAL_IP_PROBES {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(probe).is_ok() {
                if let Ok(local) = socket.local_addr() {
                    let ip = local.ip().to_string();
                    if !is_loopback(&ip) {
                        return ip;
                    }
                }
            }
        }
    }
    FALLBACK_IP.to_string()
}
