use rustls::pki_types::ServerName;
use rustls::server::Acceptor;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

use crate::configuration::{Configuration};
use crate::error::{ProxyError, ResultExt, invalid};

const UPSTREAM_PORT: u16 = 443;

pub struct Proxy {
    configuration: Configuration,
}

impl Proxy {
    pub fn new(configuration: Configuration) -> Self {
        Self { configuration }
    }

    pub async fn handle(&self, downstream_tcp: TcpStream) -> Result<(), ProxyError> {
        let start = LazyConfigAcceptor::new(Acceptor::default(), downstream_tcp)
            .await // waits for the COMPLETED ClientHello (even if it was delivered partially by tcp)
            .context("read ClientHello")?;

        let hello = start.client_hello();
        let sni = hello
            .server_name()
            .ok_or_else(|| invalid("validate ClientHello", "SNI is required"))?
            .to_owned();

        let server_name =
            ServerName::try_from(sni.clone()).context("validate upstream server name")?;

        let upstream_tcp = TcpStream::connect((sni.as_str(), UPSTREAM_PORT))
            .await
            .context("connect upstream")?;

        let connector = TlsConnector::from(self.configuration.client_config.clone());

        let mut upstream = connector
            .connect(server_name, upstream_tcp)
            .await
            .context("verify upstream TLS")?;

        let server_config = self.configuration.server_config(&sni)?;

        let mut downstream = start
            .into_stream(server_config)
            .await
            .context("complete downstream TLS")?;

        copy_bidirectional(&mut downstream, &mut upstream)
            .await
            .context("relay application bytes")?;

        Ok(())
    }
}
