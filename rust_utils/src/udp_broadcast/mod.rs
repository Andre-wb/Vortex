pub mod api;
pub mod service;

use pyo3::prelude::*;
use std::thread;
use std::time::Duration;

#[derive(Clone)]
pub struct DiscoverySettings {
    pub name: String,
    pub signaling_port: u16,
    pub udp_port: u16,
    pub interval: Duration,
    pub peer_timeout: f64,
    pub node_pubkey_hex: Option<String>,
    pub stealth: bool,
    pub network_key: Vec<u8>,
}

pub struct Shared {
    pub settings: DiscoverySettings,
}

#[pyfunction]
#[pyo3(signature = (
    name,
    signaling_port,
    udp_port,
    interval_secs,
    peer_timeout_secs,
    node_pubkey_hex = None,
    stealth = false,
    network_key = Vec::new(),
))]
#[allow(clippy::too_many_arguments)]
pub fn start_discovery(
    name: String,
    signaling_port: u16,
    udp_port: u16,
    interval_secs: f64,
    peer_timeout_secs: f64,
    node_pubkey_hex: Option<String>,
    stealth: bool,
    network_key: Vec<u8>,
) -> PyResult<()> {
    let settings = DiscoverySettings {
        name,
        signaling_port,
        udp_port,
        interval: Duration::from_secs_f64(interval_secs.max(0.001)),
        peer_timeout: peer_timeout_secs,
        node_pubkey_hex,
        stealth,
        network_key,
    };

    crate::registry::shared::set_timeout(settings.peer_timeout);

    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                log::error!("udp discovery: не удалось создать Tokio-рантайм: {}", error);
                return;
            }
        };

        runtime.block_on(async move {
            if let Err(error) = service::run_discovery(settings).await {
                log::warn!("udp discovery: обнаружение узлов прервано: {}", error);
            }
        });
    });

    Ok(())
}
