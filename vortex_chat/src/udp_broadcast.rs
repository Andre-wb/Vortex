use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tokio::time;
use once_cell::sync::Lazy;
use std::sync::{Mutex, Arc};

pub static GLOBAL_STATE: Lazy<Mutex<Option<Arc<tokio::sync::Mutex<AppState>>>>> =
    Lazy::new(|| Mutex::new(None));

pub mod discovery;

const BROADCAST_PORT: u16 = 4200;
const BROADCAST_INTERVAL: Duration = Duration::from_secs(2);
const PEER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PeerInfo {
    name: String,
    signaling_port: u16,
}

#[derive(Debug, Clone)]
struct Peer {
    info: PeerInfo,
    last_seen: tokio::time::Instant,
}

struct AppState {
    peers: HashMap<SocketAddr, Peer>,
    our_info: PeerInfo,
}

impl AppState {
    fn new(our_info: PeerInfo) -> Self {
        Self {
            peers: HashMap::new(),
            our_info,
        }
    }
    fn update_peer(&mut self, addr: SocketAddr, info: PeerInfo) {
        self.peers.insert(
            addr,
            Peer {
                info,
                last_seen: time::Instant::now(),
            }
        );
    }
    fn remove_stale_peers(&mut self) {
        let now = tokio::time::Instant::now();
        self.peers.retain(|_, peer| now.duration_since(peer.last_seen) < PEER_TIMEOUT);
    }

    fn active_peers(&self) -> Vec<(SocketAddr, PeerInfo)> {
        self.peers.iter().map(|(addr, peer)| (*addr, peer.info.clone())).collect()
    }
}