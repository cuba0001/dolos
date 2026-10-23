mod configuration;
mod error;
mod proxy;

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::configuration::Configuration;
use crate::error::{ProxyError, ResultExt};
use crate::proxy::TlsProxy;

const LISTEN_ADDR: &str = "127.0.0.1:4443";

#[tokio::main]
async fn main() -> Result<(), ProxyError> {
    let configuration = Arc::new(Configuration::load()?);

    let listener = TcpListener::bind(LISTEN_ADDR)
        .await
        .context("bind listener")?;

    loop {
        let (stream, peer) = listener.accept().await.context("accept TCP connection")?;
        let configuration = configuration.clone();

        tokio::spawn(async move {
            let result = match TlsProxy::new(configuration, stream).await {
                Ok(proxy) => proxy.handle().await,
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                eprintln!("connection failed: peer={peer}; {error}");
            }
        });
    }
}
