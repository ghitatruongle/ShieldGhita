use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub struct SilentSinkhole {
    pub absorbed_count: Arc<AtomicU64>,
}

impl SilentSinkhole {
    pub fn new() -> Self {
        Self {
            absorbed_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn start(self: Arc<Self>) {
        let ports = [80u16, 8080u16, 8888u16];
        let mut active_listener = None;

        for port in ports {
            match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                Ok(l) => {
                    info!(
                        "Silent Ad Sinkhole HTTP Server listening on 127.0.0.1:{}",
                        port
                    );
                    active_listener = Some(l);
                    break;
                }
                Err(e) => {
                    warn!("Sinkhole port {} unavailable: {}", port, e);
                }
            }
        }

        let listener = match active_listener {
            Some(l) => l,
            None => {
                warn!("Could not bind any sinkhole HTTP port. Silent sinkhole fallback active via DNS 0.0.0.0");
                return;
            }
        };

        let transparent_gif: &[u8] = &[
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00,
            0x3b,
        ];

        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };

            let counter = self.absorbed_count.clone();
            let gif_data = transparent_gif.to_vec();

            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    socket.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return,
                };

                let request = String::from_utf8_lossy(&buf[..n]);
                counter.fetch_add(1, Ordering::Relaxed);

                let response = if request.contains(".gif")
                    || request.contains(".png")
                    || request.contains(".jpg")
                    || request.contains(".webp")
                {
                    let mut resp = format!(
                        "HTTP/1.1 200 OK\r\n\
                        Content-Type: image/gif\r\n\
                        Access-Control-Allow-Origin: *\r\n\
                        Content-Length: {}\r\n\
                        Connection: close\r\n\r\n",
                        gif_data.len()
                    )
                    .into_bytes();
                    resp.extend_from_slice(&gif_data);
                    resp
                } else if request.contains(".json") {
                    let body = "{}";
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                        Content-Type: application/json\r\n\
                        Access-Control-Allow-Origin: *\r\n\
                        Content-Length: {}\r\n\
                        Connection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .into_bytes()
                } else {
                    let body = "";
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                        Content-Type: application/javascript\r\n\
                        Access-Control-Allow-Origin: *\r\n\
                        Content-Length: {}\r\n\
                        Connection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .into_bytes()
                };

                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    socket.write_all(&response),
                )
                .await;
            });
        }
    }
}
