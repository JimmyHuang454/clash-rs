use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
    pin::Pin,
    task::{Context, Poll},
    rc::Rc,
    cell::RefCell,
};

use anyhow::{Result, anyhow};
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::sleep,
};
use tracing::{error, trace, warn};

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::errors::new_io_error,
};

enum Cmd {
    Connect {
        server: String,
        port: u16,
        sni: String,
        alpn: Vec<Vec<u8>>,
        resolver: ThreadSafeDNSResolver,
        tx: oneshot::Sender<Result<u64>>, // Returns conn_id
    },
    OpenStream {
        conn_id: u64,
        tx: oneshot::Sender<Result<TQuicStream>>,
    },
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

pub struct TQuicClient {
    tx: mpsc::UnboundedSender<Cmd>,
}

impl TQuicClient {
    pub fn new(congestion_controller: Option<String>) -> Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        
        let driver = TQuicDriver::new(rx, tx.clone(), congestion_controller)?;
        std::thread::spawn(move || {
            // TQuic Endpoint is not Send, so we must run it in a dedicated thread 
            // and use a LocalSet if we want to use non-Send futures, but here we construct it inside the thread.
            // Actually, TQuic Endpoint is Send? 
            // Let's check docs. "Endpoint Instantiation ... The Endpoint is responsible for managing connections..."
            // It seems it might be Send. But the Rc<dyn PacketSendHandler> suggests it is NOT Send.
            // So we must run driver in a dedicated OS thread or use tokio::task::spawn_local.
            
            // Using a dedicated thread with a basic runtime or just a loop.
            // Since we need to use tokio socket, we need a tokio runtime.
            // spawn_blocking or new thread with new runtime.
            
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            
            rt.block_on(async {
                let mut driver = driver; // move driver here
                if let Err(e) = driver.run().await {
                    error!("TQuicDriver error: {}", e);
                }
            });
        });

        Ok(Self { tx })
    }

    pub async fn open_stream(
        &self,
        server: &str,
        port: u16,
        sni: &str,
        alpn: &[String],
        resolver: &ThreadSafeDNSResolver,
    ) -> std::io::Result<TQuicStream> {
        let (tx_conn, rx_conn) = oneshot::channel();
        self.tx.send(Cmd::Connect {
            server: server.to_string(),
            port,
            sni: sni.to_string(),
            alpn: alpn.iter().map(|s| s.as_bytes().to_vec()).collect(),
            resolver: resolver.clone(),
            tx: tx_conn,
        }).map_err(|_| new_io_error("failed to send connect cmd"))?;
        
        let conn_id = rx_conn.await.map_err(|_| new_io_error("failed to receive conn_id"))?
            .map_err(|e| new_io_error(format!("connect failed: {}", e)))?;
            
        let (tx_stream, rx_stream) = oneshot::channel();
        self.tx.send(Cmd::OpenStream { conn_id, tx: tx_stream })
            .map_err(|_| new_io_error("failed to send open stream cmd"))?;
            
        let stream = rx_stream.await.map_err(|_| new_io_error("failed to receive stream"))?
            .map_err(|e| new_io_error(format!("open stream failed: {}", e)))?;
            
        Ok(stream)
    }
}

struct TransportHandler {
    // conn_id -> stream_id -> sender
    streams: Rc<RefCell<HashMap<u64, HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>>,
    // conn_id -> handshake completion sender
    pending_handshakes: Rc<RefCell<HashMap<u64, oneshot::Sender<Result<u64>>>>>,
}

impl tquic::TransportHandler for TransportHandler {
    fn on_conn_created(&mut self, conn: &mut tquic::Connection) {
        trace!("connection created: {:?}", conn.index());
    }
    fn on_conn_established(&mut self, conn: &mut tquic::Connection) {
        trace!("connection established: {:?}", conn.index());
        if let Some(index) = conn.index() {
            if let Some(tx) = self.pending_handshakes.borrow_mut().remove(&index) {
                let _ = tx.send(Ok(index));
            }
        }
    }
    fn on_conn_closed(&mut self, conn: &mut tquic::Connection) {
        trace!("connection closed: {:?}", conn.index());
        if let Some(index) = conn.index() {
            self.streams.borrow_mut().remove(&index);
            if let Some(tx) = self.pending_handshakes.borrow_mut().remove(&index) {
                let _ = tx.send(Err(anyhow!("connection closed before established")));
            }
        }
    }
    fn on_stream_created(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        trace!("stream created: {:?} {}", conn.index(), stream_id);
    }
    fn on_stream_readable(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        let mut buf = vec![0u8; 65535];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((len, fin)) => {
                    let data = buf[..len].to_vec();
                    let mut streams = self.streams.borrow_mut();
                    if let Some(index) = conn.index() {
                        if let Some(conn_streams) = streams.get_mut(&index) {
                            if let Some(tx) = conn_streams.get_mut(&stream_id) {
                                if !data.is_empty() {
                                    let _ = tx.send(data);
                                }
                                if fin {
                                    // Signal EOF? For now we just close sending.
                                    // In real implementation we might need a special message for EOF.
                                }
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
    fn on_stream_writable(&mut self, _conn: &mut tquic::Connection, _stream_id: u64) {
    }
    fn on_stream_closed(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        if let Some(index) = conn.index() {
            if let Some(conn_streams) = self.streams.borrow_mut().get_mut(&index) {
                conn_streams.remove(&stream_id);
            }
        }
    }
    fn on_new_token(&mut self, _conn: &mut tquic::Connection, _token: Vec<u8>) {}
}

struct PacketSender {
    socket: Arc<UdpSocket>,
}

impl tquic::PacketSendHandler for PacketSender {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, tquic::PacketInfo)]) -> tquic::Result<usize> {
        let mut sent = 0;
        for (pkt, info) in pkts {
            if let Err(e) = self.socket.try_send_to(pkt, info.dst) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                error!("send packet error: {}", e);
                // Treat permanent errors as sent to avoid infinite retry loops if possible, 
                // or just break and let tquic retry.
                // For UDP, errors might be transient.
                break; 
            }
            sent += 1;
        }
        Ok(sent)
    }
}

struct TQuicDriver {
    rx: mpsc::UnboundedReceiver<Cmd>,
    tx: mpsc::UnboundedSender<Cmd>,
    next_stream_ids: HashMap<u64, u64>,
    congestion_controller: Option<String>,
}

impl TQuicDriver {
    fn new(rx: mpsc::UnboundedReceiver<Cmd>, tx: mpsc::UnboundedSender<Cmd>, congestion_controller: Option<String>) -> Result<Self> {
        Ok(Self { rx, tx, next_stream_ids: HashMap::new(), congestion_controller })
    }
    
    async fn run(&mut self) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        
        let streams = Rc::new(RefCell::new(HashMap::new()));
        let pending_handshakes = Rc::new(RefCell::new(HashMap::new()));
        
        let handler = Box::new(TransportHandler {
            streams: streams.clone(),
            pending_handshakes: pending_handshakes.clone(),
        });
        
        let sender = Rc::new(PacketSender {
            socket: socket.clone(),
        });
        
        let mut config = tquic::Config::new()?;
        if let Some(cc) = &self.congestion_controller {
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
        config.set_max_idle_timeout(30000);
        
        let mut endpoint = tquic::Endpoint::new(Box::new(config), false, handler, sender);
        
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
                    endpoint.recv(&mut buf[..len], &info)?;
                    endpoint.process_connections()?;
                }
                cmd = self.rx.recv() => {
                    if let Some(cmd) = cmd {
                        match cmd {
                            Cmd::Connect { server, port, sni, alpn, resolver, tx } => {
                                // Resolve IP
                                let ip_res = resolver.resolve(&server, false).await;
                                match ip_res {
                                    Ok(Some(ip)) => {
                                        let addr = SocketAddr::new(ip, port);
                                        let local = socket.local_addr()?;
                                        
                                        // Configure TLS
                                        let mut tls_config = match tquic::TlsConfig::new() {
                                            Ok(c) => c,
                                            Err(e) => {
                                                let _ = tx.send(Err(anyhow!("tls config error: {}", e)));
                                                continue;
                                            }
                                        };
                                        if let Err(e) = tls_config.set_application_protos(alpn) {
                                            let _ = tx.send(Err(anyhow!("set alpn error: {}", e)));
                                            continue;
                                        }
                                        // TODO: set sni, skip_verify
                                        
                                        let mut conn_conf = match tquic::Config::new() {
                                            Ok(mut c) => {
                                                if let Some(cc) = &self.congestion_controller {
                                                    match cc.to_lowercase().as_str() {
                                                        "bbr" => c.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Bbr),
                                                        "bbr3" => c.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Bbr3),
                                                        "cubic" => c.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Cubic),
                                                        "copa" => c.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Copa),
                                                        _ => {
                                                            warn!("unsupported congestion controller: {}, using BBR", cc);
                                                            c.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Bbr);
                                                        }
                                                    }
                                                } else {
                                                    c.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Bbr);
                                                }
                                                // c.set_max_idle_timeout(30000);
                                                // c.set_initial_max_streams_bidi(100);
                                                // c.set_initial_max_data(10_000_000_000);
                                                // c.set_initial_max_stream_data_bidi_local(5_000_000_000);
                                                // c.set_initial_max_stream_data_bidi_remote(5_000_000_000);
                                                // c.set_initial_congestion_window(2048);
                                                // c.set_min_congestion_window(512);
                                                c
                                            },
                                            Err(e) => {
                                                let _ = tx.send(Err(anyhow!("quic config error: {}", e)));
                                                continue;
                                            }
                                        };
                                        conn_conf.set_tls_config(tls_config);
                                        
                                        match endpoint.connect(local, addr, Some(&sni), None, None, Some(&conn_conf)) {
                                            Ok(conn_index) => {
                                                self.next_stream_ids.insert(conn_index, 0);
                                                pending_handshakes.borrow_mut().insert(conn_index, tx);
                                                endpoint.process_connections()?;
                                            },
                                            Err(e) => {
                                                let _ = tx.send(Err(anyhow!("connect failed: {}", e)));
                                            }
                                        }
                                    },
                                    Ok(None) => { let _ = tx.send(Err(anyhow!("dns resolve empty"))); },
                                    Err(e) => { let _ = tx.send(Err(anyhow!("dns resolve failed: {}", e))); }
                                }
                            }
                            Cmd::OpenStream { conn_id, tx } => {
                                if endpoint.conn_get_mut(conn_id).is_some() {
                                    let stream_id = *self.next_stream_ids.entry(conn_id).or_insert(0);
                                    *self.next_stream_ids.get_mut(&conn_id).unwrap() += 4;

                                    let (tx_stream, rx_stream) = mpsc::unbounded_channel();

                                    {
                                        let mut streams_map = streams.borrow_mut();
                                        let conn_streams = streams_map.entry(conn_id).or_insert_with(HashMap::new);
                                        conn_streams.insert(stream_id, tx_stream);
                                    }

                                    let stream = TQuicStream {
                                        tx: self.tx.clone(),
                                        rx: rx_stream,
                                        conn_id,
                                        stream_id,
                                        buffer: Bytes::new(),
                                    };

                                    let _ = tx.send(Ok(stream));
                                } else {
                                    let _ = tx.send(Err(anyhow!("connection not found")));
                                }
                            }
                            Cmd::WriteStream { conn_id, stream_id, data, fin } => {
                                if let Some(conn) = endpoint.conn_get_mut(conn_id) {
                                    match conn.stream_write(stream_id, Bytes::from(data), fin) {
                                        Ok(_) => {},
                                        Err(tquic::Error::Done) => {},
                                        Err(e) => error!("stream write error: {}", e),
                                    }
                                    endpoint.process_connections()?;
                                }
                            }
                            Cmd::CloseStream { conn_id, stream_id } => {
                                if let Some(conn) = endpoint.conn_get_mut(conn_id) {
                                    // Close stream write side
                                    let _ = conn.stream_shutdown(stream_id, tquic::Shutdown::Write, 0);
                                    endpoint.process_connections()?;
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }
                _ = async {
                    if let Some(t) = timeout {
                        sleep(t).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    endpoint.on_timeout(Instant::now());
                    endpoint.process_connections()?;
                }
            }
        }
        Ok(())
    }
}

pub struct TQuicStream {
    tx: mpsc::UnboundedSender<Cmd>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    conn_id: u64,
    stream_id: u64,
    buffer: Bytes,
}

impl AsyncRead for TQuicStream {
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

impl AsyncWrite for TQuicStream {
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
        
        match self.tx.send(cmd) {
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
        match self.tx.send(cmd) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "driver closed"))),
        }
    }
}
