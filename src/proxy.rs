use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::server::Acceptor;
use tokio::io::{AsyncReadExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

use crate::configuration::Configuration;
use crate::error::{ProxyError, ResultExt, invalid};

const UPSTREAM_PORT: u16 = 443;
const TLS_HANDSHAKE_FIRST_BYTE: u8 = 0x16;
const CONNECT_PREFIX: &[u8] = b"CONNECT ";
const INITIAL_READ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONNECT_HEADER: usize = 32 * 1024;

pub struct TlsProxy {
    configuration: Arc<Configuration>,
    is_tls: bool,
    raw_downstream: TcpStream,
}

impl TlsProxy {
    pub async fn new(
        configuration: Arc<Configuration>,
        stream: TcpStream,
    ) -> Result<Self, ProxyError> {
        let is_tls = Self::is_tls(&stream).await?;
        Ok(Self {
            configuration,
            is_tls,
            raw_downstream: stream,
        })
    }

    pub async fn handle(mut self) -> Result<(), ProxyError> {
        if self.is_tls {
            self.handle_tls_stream().await
        } else {
            self.handle_other_stream().await
        }
    }

    async fn is_tls(stream: &TcpStream) -> Result<bool, ProxyError> {
        let mut first_byte = [0];

        let received = timeout(INITIAL_READ_TIMEOUT, stream.peek(&mut first_byte))
            .await
            .context("wait for first byte")?
            .context("inspect incoming connection")?;

        if received == 0 {
            return Err(invalid("inspect incoming connection", "connection closed"));
        }

        Ok(first_byte[0] == TLS_HANDSHAKE_FIRST_BYTE)
    }

    async fn handle_tls_stream(self) -> Result<(), ProxyError> {
        let start = LazyConfigAcceptor::new(Acceptor::default(), self.raw_downstream)
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

    async fn handle_other_stream(&mut self) -> Result<(), ProxyError> {
        let deadline = Instant::now() + INITIAL_READ_TIMEOUT;
        let mut buff = Vec::new();
        let mut chunk = [0; 1024];

        loop {
            let received = timeout_at(deadline, self.raw_downstream.read(&mut chunk))
                .await
                .context("read initial bytes")?
                .context("read initial bytes")?;

            if received == 0 {
                Err(invalid(
                    "read initial bytes",
                    "no received bytes on initial read",
                ))?
            }

            buff.extend_from_slice(&chunk[..received]);

            if buff.starts_with(CONNECT_PREFIX) {
                if let Some(header_ends_at) = Self::find_connect_header_ends(&buff) {
                    let connect_header = &buff[..header_ends_at];
                    let (host, port) = Self::parse_connect_header(connect_header)?;

                    self.handle_connect(&buff).await?
                }
            }

            if buff.len() >= MAX_CONNECT_HEADER {
                Err(invalid(
                    "handle other stream",
                    "min useful amounts of bytes reached",
                ))?
            }
        }
    }

    async fn handle_connect(&mut self, _initial_bytes: &Vec<u8>) -> Result<(), ProxyError> {
        Ok(())
    }

    fn find_connect_header_ends(buf: &[u8]) -> Option<usize> {
        buf.windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|pos| pos + 4)
    }

    fn parse_connect_header(connect_header: &[u8]) -> Result<(String, u16), ProxyError> {
        let header = std::str::from_utf8(connect_header).context("parse CONNECT header")?;

        let authority = header
            .split_ascii_whitespace()
            .nth(1)
            .ok_or_else(|| invalid("parse CONNECT", "host:port is missing"))?;

        let (host, port) = authority
            .split_once(':')
            .ok_or_else(|| invalid("parse CONNECT", "expected host:port"))?;

        let port = port.parse::<u16>().context("parse CONNECT port")?;

        Ok((host.to_owned(), port))
    }
}
