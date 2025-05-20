use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::AuraState;

/// Spawn a very simple HTTP RPC server providing `/status` endpoint.
pub fn spawn_rpc_server(state: Arc<Mutex<AuraState>>, listen_addr: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(l) => {
                info!(addr = %listen_addr, "RPC server listening");
                l
            }
            Err(e) => {
                error!("Failed to bind RPC server: {}", e);
                return;
            }
        };

        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("RPC accept error: {}", e);
                    continue;
                }
            };

            let mut buf = [0u8; 1024];
            match socket.read(&mut buf).await {
                Ok(0) => {}
                Ok(_) => {
                    let height = {
                        let guard = state.lock().unwrap();
                        guard.height_value()
                    };
                    let body = format!("{{\"height\":{}}}", height);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if let Err(e) = socket.write_all(response.as_bytes()).await {
                        error!("RPC write error: {}", e);
                    }
                }
                Err(e) => {
                    error!("RPC read error: {}", e);
                }
            }
        }
    })
}
