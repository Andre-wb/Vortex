use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{self, Duration};
use crate::udp_broadcast::{AppState, PeerInfo, BROADCAST_PORT, BROADCAST_INTERVAL};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let name = if args.len() > 1 {
        args[1].clone()
    } else {
        whoami::hostname()
    };
    let signaling_port = 9000;
    let our_info = PeerInfo {
        name,
        signaling_port,
    };
    let send_socket = UdpSocket::bind("0.0.0.0:0").await?;
    send_socket.set_broadcast(true)?;
    let recv_socket = UdpSocket::bind(format!("0.0.0.0:{}", BROADCAST_PORT)).await?;
    let state = Arc::new(Mutex::new(AppState::new(our_info)));
    let send_state = state.clone();
    let send_handle = tokio::spawn(async move {
        if let Err(e) = run_sender(send_socket, send_state).await {
            eprintln!("Sender error: {}", e);
        }
    });
    let recv_state = state.clone();
    let recv_handle = tokio::spawn(async move {
        if let Err(e) = run_receiver(recv_socket, recv_state).await {
            eprintln!("Receiver error: {}", e);
        }
    });
    let cleanup_state = state.clone();
    let cleanup_handle = tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let mut state = cleanup_state.lock().await;
            state.remove_stale_peers();
            let peers = state.active_peers();
            println!("Active peers {}:", peers.len());
            for (addr, info) in peers {
                println!("{}: ({}): signaling port {}", info.name, addr.ip(), info.signaling_port);
            }
        }
    });
    tokio::select! {
        _ = send_handle => {},
        _ = recv_handle => {},
        _ = cleanup_handle => {},
    }

    Ok(())
}

async fn run_sender(socket: UdpSocket, state: Arc<Mutex<AppState>>) -> Result<(), Box<dyn std::error::Error>> {
    let broadcast_addr: SocketAddr = format!("255.255.255.255:{}", BROADCAST_PORT).parse()?;
    let mut interval = time::interval(BROADCAST_INTERVAL);

    loop {
        interval.tick().await;

        let info = {
            let state = state.lock().await;
            state.our_info.clone()
        };
        let data = serde_json::to_vec(&info)?;
        if let Err(e) = socket.send_to(&data, broadcast_addr).await {
            eprintln!("Failed to send broadcast: {}", e);
        } else {
            println!("Broadcast sent: {:?}", info);
        }
    }
}

async fn run_receiver(socket: UdpSocket, state: Arc<Mutex<AppState>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 1024];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, src_addr)) => {
                match serde_json::from_slice::<PeerInfo>(&buf[..size]) {
                    Ok(info) => {
                        let mut state = state.lock().await;
                        state.update_peer(src_addr, info.clone());
                        println!("Received from {}: {:?}", src_addr, info);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse peer info from {}: {}", src_addr, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving datagram: {}", e);
            }
        }
    }
}