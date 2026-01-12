use std::sync::Arc;
use std::net::SocketAddr;
use std::fs;
use std::io::{self, BufReader};
use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::Instant;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncRead, AsyncWrite, ReadBuf};
use tracing::{warn, error, trace, info};
use sha2::{Digest, Sha224};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tokio::sync::mpsc;
use tokio::net::UdpSocket;
use bytes::Bytes;

use crate::proxy::inbound::InboundHandlerTrait;
use crate::Dispatcher;
use crate::common::auth::ThreadSafeAuthenticator;
use crate::session::{Session, Network, Type, SocksAddr};
use crate::proxy::utils::{try_create_dualstack_tcplistener, apply_tcp_options, ToCanonical};

pub struct TrojanInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    _authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
    password: String,
    certificate: String,
    private_key: String,
    alpn: Vec<String>,
    network: Option<String>,
    congestion_controller: Option<String>,
}

impl TrojanInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        fw_mark: Option<u32>,
        password: String,
        certificate: String,
        private_key: String,
        alpn: Vec<String>,
        network: Option<String>,
        congestion_controller: Option<String>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            _authenticator: authenticator,
            fw_mark,
            password,
            certificate,
            private_key,
            alpn,
            network,
            congestion_controller,
        }
    }

    fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
        let file = fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn load_keys(path: &str) -> io::Result<PrivateKeyDer<'static>> {
        let file = fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        rustls_pemfile::private_key(&mut reader)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))
    }
}

#[async_trait]
impl InboundHandlerTrait for TrojanInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        self.network.as_deref() == Some("tquic")
    }

    async fn listen_tcp(&self) -> io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;
        
        let certs = Self::load_certs(&self.certificate)?;
        let key = Self::load_keys(&self.private_key)?;

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            
        if !self.alpn.is_empty() {
            config.alpn_protocols = self.alpn.iter().map(|x| x.as_bytes().to_vec()).collect();
        }

        let acceptor = TlsAcceptor::from(Arc::new(config));

        loop {
            let (socket, _) = listener.accept().await?;
            let src_addr = match socket.peer_addr() {
                Ok(a) => a.to_canonical(),
                Err(e) => {
                    warn!("failed to get peer address: {}", e);
                    continue;
                }
            };

            if !self.allow_lan && src_addr.ip() != socket.local_addr()?.ip().to_canonical() {
                warn!("Connection from {} is not allowed", src_addr);
                continue;
            }

            apply_tcp_options(&socket)?;

            let acceptor = acceptor.clone();
            let dispatcher = self.dispatcher.clone();
            let password = self.password.clone();
            let fw_mark = self.fw_mark;

            tokio::spawn(async move {
                let mut stream = match acceptor.accept(socket).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("TLS handshake failed: {}", e);
                        return;
                    }
                };

                // Handshake
                // 56 bytes hash + CRLF
                let mut buf = [0u8; 58];
                if let Err(e) = stream.read_exact(&mut buf).await {
                    warn!("failed to read trojan header: {}", e);
                    return;
                }

                if &buf[56..58] != b"\r\n" {
                    warn!("invalid trojan header: CRLF missing");
                    return;
                }

                let hash = String::from_utf8_lossy(&buf[0..56]);
                let expected_hash = {
                    let mut hasher = Sha224::new();
                    hasher.update(password.as_bytes());
                    crate::common::utils::encode_hex(&hasher.finalize())
                };

                if hash != expected_hash {
                    warn!("trojan auth failed");
                    return;
                }

                // Command
                let cmd = match stream.read_u8().await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("failed to read command: {}", e);
                        return;
                    }
                };

                if cmd != 1 { // CONNECT
                     warn!("unsupported trojan command: {}", cmd);
                     // We could support UDP (3) but let's stick to TCP (1) for now
                     return;
                }

                // Address
                let addr = match SocksAddr::read_from(&mut stream).await {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("failed to read address: {}", e);
                        return;
                    }
                };
                
                // CRLF
                let mut crlf = [0u8; 2];
                if let Err(e) = stream.read_exact(&mut crlf).await {
                     warn!("failed to read CRLF after address: {}", e);
                     return;
                }
                if &crlf != b"\r\n" {
                    warn!("invalid trojan header: CRLF missing after address");
                    return;
                }

                let sess = Session {
                    network: Network::Tcp,
                    typ: Type::Trojan,
                    source: src_addr,
                    destination: addr,
                    so_mark: fw_mark,
                    ..Default::default()
                };

                dispatcher.dispatch_stream(sess, Box::new(stream)).await;
            });
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        if self.network.as_deref() != Some("tquic") {
            return Err(io::Error::new(io::ErrorKind::Other, "Trojan UDP inbound not supported yet"));
        }

        let addr = self.addr;
        let cert_path = self.certificate.clone();
        let key_path = self.private_key.clone();
        let alpn = self.alpn.clone();
        let dispatcher = self.dispatcher.clone();
        let password = self.password.clone();
        let fw_mark = self.fw_mark;
        let congestion_controller = self.congestion_controller.clone();

        // Spawn a thread to run the TQuic loop on a dedicated thread with current_thread runtime
        // We use std::thread::spawn instead of tokio::task::spawn_blocking to avoid blocking
        // the runtime shutdown, as this loop is infinite and doesn't check for shutdown signals.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
            
            if let Err(e) = rt {
                error!("failed to create runtime for tquic inbound: {}", e);
                return;
            }
            let rt = rt.unwrap();

            let res = rt.block_on(async {
                // Try to set SO_REUSEADDR and SO_REUSEPORT
                let socket = socket2::Socket::new(
                    if addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 },
                    socket2::Type::DGRAM,
                    None,
                )?;
                
                socket.set_nonblocking(true)?;
                socket.set_reuse_address(true)?;
                #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
                socket.set_reuse_port(true)?;

                socket.bind(&addr.into())?;
                let socket = Arc::new(UdpSocket::from_std(socket.into())?);
                info!("Trojan TQuic listening on {}", addr);

                let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
                let streams = Rc::new(RefCell::new(HashMap::new()));
                
                let handler = Box::new(ServerHandler {
                    streams: streams.clone(),
                    dispatcher,
                    password,
                    fw_mark,
                    cmd_tx: cmd_tx.clone(),
                });

                let sender = Rc::new(ServerPacketSender {
                    socket: socket.clone(),
                });

                let mut config = tquic::Config::new()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tquic config error: {}", e)))?;
                
                if let Some(cc) = &congestion_controller {
                    match cc.to_lowercase().as_str() {
                        "bbr" => config.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Bbr),
                        "bbr3" => config.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Bbr3),
                        "cubic" => config.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Cubic),
                        "copa" => config.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Copa),
                        _ => {
                            warn!("unsupported congestion controller: {}, using BBR", cc);
                            config.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Bbr);
                        }
                    }
                } else {
                    config.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Bbr);
                }

                // config.set_max_idle_timeout(30000);
                // config.set_initial_max_streams_bidi(100);
                // config.set_initial_max_data(10_000_000_000);
                // config.set_initial_max_stream_data_bidi_local(5_000_000_000);
                // config.set_initial_max_stream_data_bidi_remote(5_000_000_000);
                // config.set_initial_congestion_window(2048);
                // config.set_min_congestion_window(512);

                let tls_config = tquic::TlsConfig::new_server_config(
                    &cert_path,
                    &key_path,
                    alpn.iter().map(|s| s.as_bytes().to_vec()).collect(),
                    false,
                ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls config error: {}", e)))?;

                config.set_tls_config(tls_config);

                let mut endpoint = tquic::Endpoint::new(Box::new(config), true, handler, sender);
                
                let mut buf = vec![0u8; 65535];

                loop {
                    let timeout = endpoint.timeout();
                    
                    tokio::select! {
                        res = socket.recv_from(&mut buf) => {
                            let (len, addr) = res?;
                            let info = tquic::PacketInfo {
                                src: addr,
                                dst: socket.local_addr()?,
                                time: Instant::now(),
                            };
                            if let Err(e) = endpoint.recv(&mut buf[..len], &info) {
                                trace!("tquic recv error: {}", e);
                            }
                            endpoint.process_connections().ok();
                        }
                        cmd = cmd_rx.recv() => {
                            if let Some(cmd) = cmd {
                                match cmd {
                                    Cmd::WriteStream { conn_id, stream_id, data, fin } => {
                                        if let Some(conn) = endpoint.conn_get_mut(conn_id) {
                                            match conn.stream_write(stream_id, Bytes::from(data), fin) {
                                                Ok(_) => {},
                                                Err(tquic::Error::Done) => {},
                                                Err(e) => error!("stream write error: {}", e),
                                            }
                                            endpoint.process_connections().ok();
                                        }
                                    }
                                    Cmd::CloseStream { conn_id, stream_id } => {
                                        if let Some(conn) = endpoint.conn_get_mut(conn_id) {
                                            let _ = conn.stream_shutdown(stream_id, tquic::Shutdown::Write, 0);
                                            endpoint.process_connections().ok();
                                        }
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                        _ = async {
                            if let Some(t) = timeout {
                                tokio::time::sleep(t).await;
                            } else {
                                std::future::pending::<()>().await;
                            }
                        } => {
                            endpoint.on_timeout(Instant::now());
                            endpoint.process_connections().ok();
                        }
                    }
                }
                Ok::<(), io::Error>(())
            });
            
            if let Err(e) = res {
                error!("Trojan TQuic inbound loop error: {}", e);
            }
        });
        
        Ok(())
    }
}

enum Cmd {
    WriteStream {
        conn_id: u64,
        stream_id: u64,
        data: Vec<u8>,
        fin: bool,
    },
    CloseStream {
        conn_id: u64,
        stream_id: u64,
    },
}

struct ServerHandler {
    streams: Rc<RefCell<HashMap<(u64, u64), mpsc::UnboundedSender<Vec<u8>>>>>,
    dispatcher: Arc<Dispatcher>,
    password: String,
    fw_mark: Option<u32>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
}

impl tquic::TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, _conn: &mut tquic::Connection) {}
    fn on_conn_established(&mut self, _conn: &mut tquic::Connection) {}
    fn on_conn_closed(&mut self, conn: &mut tquic::Connection) {
        if let Some(index) = conn.index() {
             // We should remove all streams for this conn, but we iterate map?
             // Or just let them error on write.
             // Ideally cleanup map.
             let mut streams = self.streams.borrow_mut();
             streams.retain(|(cid, _), _| *cid != index);
        }
    }
    fn on_stream_created(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        if let Some(index) = conn.index() {
            let (tx, rx) = mpsc::unbounded_channel();
            self.streams.borrow_mut().insert((index, stream_id), tx);

            let stream_wrapper = TQuicInboundStream {
                conn_id: index,
                stream_id,
                rx,
                cmd_tx: self.cmd_tx.clone(),
                buffer: Bytes::new(),
            };

            let dispatcher = self.dispatcher.clone();
            let password = self.password.clone();
            let fw_mark = self.fw_mark;
            let src_addr = "0.0.0.0:0".parse().unwrap();
            tokio::spawn(async move {
                handle_trojan_stream(stream_wrapper, dispatcher, password, fw_mark, src_addr).await;
            });
        }
    }
    fn on_stream_readable(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        let mut buf = vec![0u8; 65535];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((len, fin)) => {
                    let data = buf[..len].to_vec();
                    if let Some(index) = conn.index() {
                        let mut streams = self.streams.borrow_mut();
                        if let Some(tx) = streams.get_mut(&(index, stream_id)) {
                             if !data.is_empty() {
                                 let _ = tx.send(data);
                             }
                             if fin {
                                 // EOF?
                             }
                        }
                    }
                }
                Err(tquic::Error::Done) => break,
                Err(tquic::Error::StreamReset(0)) => break,
                Err(e) => {
                    error!("stream read error: {}", e);
                    break;
                }
            }
        }
    }
    fn on_stream_writable(&mut self, _conn: &mut tquic::Connection, _stream_id: u64) {}
    fn on_stream_closed(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        if let Some(index) = conn.index() {
            self.streams.borrow_mut().remove(&(index, stream_id));
        }
    }
    fn on_new_token(&mut self, _conn: &mut tquic::Connection, _token: Vec<u8>) {}
}

struct ServerPacketSender {
    socket: Arc<UdpSocket>,
}

impl tquic::PacketSendHandler for ServerPacketSender {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, tquic::PacketInfo)]) -> tquic::Result<usize> {
        let mut sent = 0;
        for (pkt, info) in pkts {
            if let Err(e) = self.socket.try_send_to(pkt, info.dst) {
                 if e.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                // error!("server: send packet error: {}", e);
                break;
            }
            sent += 1;
        }
        Ok(sent)
    }
}

struct TQuicInboundStream {
    conn_id: u64,
    stream_id: u64,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    buffer: Bytes,
}

impl AsyncRead for TQuicInboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.buffer.is_empty() {
            let len = std::cmp::min(self.buffer.len(), buf.remaining());
            buf.put_slice(&self.buffer[..len]);
            self.buffer = self.buffer.slice(len..);
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let data = Bytes::from(data);
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.buffer = data.slice(len..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TQuicInboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
         let cmd = Cmd::WriteStream {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data: buf.to_vec(),
            fin: false,
        };
        
        match self.cmd_tx.send(cmd) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "driver closed"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
         let cmd = Cmd::CloseStream {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
        };
        match self.cmd_tx.send(cmd) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "driver closed"))),
        }
    }
}

async fn handle_trojan_stream(mut stream: TQuicInboundStream, dispatcher: Arc<Dispatcher>, password: String, fw_mark: Option<u32>, src_addr: SocketAddr) {
    // Handshake
    // 56 bytes hash + CRLF
    let mut buf = [0u8; 58];
    if let Err(e) = stream.read_exact(&mut buf).await {
        warn!("failed to read trojan header: {}", e);
        return;
    }

    if &buf[56..58] != b"\r\n" {
        warn!("invalid trojan header: CRLF missing");
        return;
    }

    let hash = String::from_utf8_lossy(&buf[0..56]);
    let expected_hash = {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        crate::common::utils::encode_hex(&hasher.finalize())
    };

    if hash != expected_hash {
        warn!("trojan auth failed");
        return;
    }

    // Command
    let cmd = match stream.read_u8().await {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to read command: {}", e);
            return;
        }
    };

    if cmd != 1 { // CONNECT
            warn!("unsupported trojan command: {}", cmd);
            return;
    }

    // Address
    let addr = match SocksAddr::read_from(&mut stream).await {
        Ok(a) => a,
        Err(e) => {
            warn!("failed to read address: {}", e);
            return;
        }
    };
    
    // CRLF
    let mut crlf = [0u8; 2];
    if let Err(e) = stream.read_exact(&mut crlf).await {
            warn!("failed to read CRLF after address: {}", e);
            return;
    }
    if &crlf != b"\r\n" {
        warn!("invalid trojan header: CRLF missing after address");
        return;
    }

    let sess = Session {
        network: Network::Tcp, // TQuic carries TCP stream essentially
        typ: Type::Trojan,
        source: src_addr,
        destination: addr,
        so_mark: fw_mark,
        ..Default::default()
    };

    dispatcher.dispatch_stream(sess, Box::new(stream)).await;
}
