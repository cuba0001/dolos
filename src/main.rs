mod configuration;
mod error;
mod proxy;

use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::configuration::{Configuration};
use crate::error::{ProxyError, ResultExt};
use crate::proxy::Proxy;

const LISTEN_ADDR: &str = "127.0.0.1:4443";

#[tokio::main]
async fn main() -> Result<(), ProxyError> {
    let configuration = Configuration::load()?;

    let proxy = Arc::new(Proxy::new(configuration));

    let listener = TcpListener::bind(LISTEN_ADDR)
        .await
        .context("bind listener")?;

    loop {
        let (stream, peer) = listener.accept().await.context("accept TCP connection")?;
        let proxy = proxy.clone();
        tokio::spawn(async move {
            if let Err(error) = proxy.handle(stream).await {
                eprintln!("connection failed: peer={peer}; {error}");
            }
        });
    }
}
