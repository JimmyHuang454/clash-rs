use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
    pin::Pin,
    task::{Context, Poll},
};

use quinn::{ClientConfig as QuinnConfig, Connection, Endpoint as QuinnEndpoint, TokioRuntime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;
use tracing::debug;

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::{tls::DefaultTlsVerifier, errors::new_io_error},
    proxy::utils::new_udp_socket,
};

pub struct QuicClient {
    endpoint: AsyncMutex<Option<QuinnEndpoint>>,
    connection: AsyncMutex<Option<Connection>>,
    server: String,
    port: u16,
    sni: String,
    alpn: Vec<Vec<u8>>,
    skip_cert_verify: bool,
    ipv6: AtomicBool,
}

impl QuicClient {
    pub fn new(
        server: String,
        port: u16,
        sni: String,
        alpn: Vec<String>,
        skip_cert_verify: bool,
    ) -> Self {
        Self {
            endpoint: AsyncMutex::new(None),
            connection: AsyncMutex::new(None),
            server,
            port,
            sni,
            alpn: alpn.into_iter().map(|x| x.into_bytes()).collect(),
            skip_cert_verify,
            ipv6: AtomicBool::new(false),
        }
    }

    async fn get_connection(&self, resolver: &ThreadSafeDNSResolver) -> std::io::Result<Connection> {
        let mut connection_guard = self.connection.lock().await;
        if let Some(conn) = connection_guard.as_ref() {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }

        let ip = resolver
            .resolve(&self.server, false)
            .await
            .map_err(|e| new_io_error(format!("failed to resolve {}: {}", self.server, e)))?
            .ok_or_else(|| new_io_error(format!("failed to resolve {}", self.server)))?;

        let addr = SocketAddr::new(ip, self.port);
        let ipv6 = addr.is_ipv6();

        let mut endpoint_guard = self.endpoint.lock().await;
        
        let need_new_endpoint = endpoint_guard.is_none() || self.ipv6.load(Ordering::Relaxed) != ipv6;
        
        if need_new_endpoint {
            self.ipv6.store(ipv6, Ordering::Relaxed);
            let bind_addr = if ipv6 {
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
            };
            
            let socket = new_udp_socket(Some(bind_addr.into()), None, None).await?;
            let mut endpoint = QuinnEndpoint::new(
                Default::default(),
                None,
                socket.into_std()?,
                Arc::new(TokioRuntime),
            )
            .map_err(|e| new_io_error(format!("failed to create quic endpoint: {}", e)))?;
            
            let verifier = DefaultTlsVerifier::new(None, self.skip_cert_verify);
            let mut crypto = rustls::client::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            
            crypto.alpn_protocols = self.alpn.clone();
            crypto.enable_early_data = true;

            let mut client_config = QuinnConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                    .map_err(|e| new_io_error(format!("failed to create quic config: {}", e)))?,
            ));
            
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
            transport_config.keep_alive_interval(Some(Duration::from_secs(10)));
            client_config.transport_config(Arc::new(transport_config));

            endpoint.set_default_client_config(client_config);
            *endpoint_guard = Some(endpoint);
        }

        let endpoint = endpoint_guard.as_ref().unwrap();
        
        debug!("connecting to quic server {} at {}", self.server, addr);
        let connecting = endpoint.connect(addr, &self.sni)
            .map_err(|e| new_io_error(format!("failed to connect quic: {}", e)))?;
            
        let conn = connecting.await
            .map_err(|e| new_io_error(format!("failed to establish quic connection: {}", e)))?;

        *connection_guard = Some(conn.clone());
        Ok(conn)
    }

    pub async fn open_stream(&self, resolver: &ThreadSafeDNSResolver) -> std::io::Result<QuicStream> {
        let conn = self.get_connection(resolver).await?;
        let (send, recv) = conn.open_bi().await.map_err(|e| new_io_error(format!("failed to open quic stream: {}", e)))?;
        Ok(QuicStream { send, recv })
    }
}

pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf).map_err(Into::into)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx).map_err(Into::into)
    }
}
