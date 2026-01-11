use std::{
    sync::Arc,
    time::Instant,
    rc::Rc,
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
use tracing::{error, info};
use tempfile::NamedTempFile;
use std::io::Write;

use crate::proxy::trojan::tquic::TQuicClient;
use crate::app::dns::SystemResolver;
use crate::proxy::trojan::{Handler as TrojanOutbound, HandlerOptions};
use crate::proxy::HandlerCommonOptions;
use crate::session::{Session, SocksAddr};

const CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgIULH/70PMQo1WnkVRLWuEv5sN+aJ8wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDExMTEzMjkxM1oXDTI3MDEx
MTEzMjkxM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEA+JN588uEhYq222fr5wqR2oUuD2hwCY+AKFEpPrT5ujRv
7TtSvqqWGN8UWg61LWJJMp1yrcMDuqSw3mt5x2VepUu8jizRkCm83bgvYQmu9YnH
6p9iVtZBSexMENln71s11oLmCz4xhuMoQ5BdaC/XaIxWz4sVB5aDcDkRSomhwIG4
eVKlU3jC4pehTXIEMVS/Plsf7CdGqs9b+FxO3AkvLgQAutE61RqdEQ+ZYgmY3L0a
ZjtuKwR76xsE2GjT/nzZFr4zwZ5Kl7VJuUZoHE8Bxo+wEFSeGL+Lpc3lUSg9UcnF
8X0f9dWoltvGBcwcyx8nsNFLHx2Q8QMvm6z8fY5dkJhVkC2GD9YmQvdDVe0KNh/J
mbH7vO2fwXFi2mNnimy5pKsj9tk/ICUo3tiITSro6xF1E7PJEs5pe7RGHcobIjgO
/oyHCdxUX5vwb7kYBk2u5JoTf/p5bs77mzMuA4oHoPBaSoxOO0KF/KHg3rkjABeV
Qf0aO/C++WrZxaa7Cs1VJpUKGfUhDcPJ99DgjUOGZV5LQO92bP7f1hZHyRvaWgq0
oF9z7EU2ViVWDqoIFrybsMPbe4ll9pmYbuVqwKGBu1QS5z9q4awGas+/KqqKwghL
ZnX/uKNCIkmysidu5lXUbD3Crv8u/DTw+WPPjh/fZsoZ4meglU9/RtvQt7/FThsC
AwEAAaNTMFEwHQYDVR0OBBYEFKz+gRJo8Wi6vx+S6vqin/KLAO10MB8GA1UdIwQY
MBaAFKz+gRJo8Wi6vx+S6vqin/KLAO10MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggIBAE8LRbw7TgWcpBwzbWqU4sT1IUffXXHem/jQ+SHUp2tqgKmP
d+PxTfPtna7fQVoSAsNl2ftNd2k6EzQRj+ebADgxN5SoMomBDbSuALNccQikE5Vo
0b5KxOoACkGsSi6rFodNWrvZ4J+eOUtRBYTrPTjIph1SyJX7BXd5j+zX7bt+B9d8
juC3MMaWD43SOZW/v+oUjN25xaUggVFOFqDJfV9+N43iUhpuC5JBdN1Fj8+man4/
l8dcRr4TdUYMGfm8C9mxXTVRgTMd3qLALauPAqz6SJT5x74S71JSLfKv9uOYU5Hk
ytp2Dix1fSnyhK9w/HHufFZ2LqZttPOnDHs4ujkQIt9DAwcTWk013Wn7N8lBBFcA
EtS6DT0pxoEbFH7SHiq/bW+erNIMtLhsM+RRrGrq1FOw/JYM4jUmu3FX6h7v0wJT
IR/q6LDzizWU1TRT1Y9BU+vdbuyG7Im4Ryf6C58lm3gXvbn0FrE+2aI9pX6GPwsE
opgymplkCNF2RXi+PnN2jWMD9ubF5hrLnoNBZl3cX+ZHdTlGXffx3NawttFPB4bZ
wZuiD3XnhwsmBseVcc2BaaZ0O5hEdySAe68tNIezoG/n1DMV8k852p1O98s+yqMr
G4voubEx82pZ8gH3kbO6msG9+SfiKjNH/V5C+ytS7Coe9f5A+nLGBqSXhFEX
-----END CERTIFICATE-----
"#;

const KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
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
3BIbSSuQWJ5l/5aSfFXJHukRxAXVJ8w=
-----END PRIVATE KEY-----
"#;

struct ServerHandler {
    // We will just echo data for any stream
}

impl tquic::TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut tquic::Connection) {
        info!("server: connection created: {:?}", conn.index());
    }
    fn on_conn_established(&mut self, conn: &mut tquic::Connection) {
        info!("server: connection established: {:?}", conn.index());
    }
    fn on_conn_closed(&mut self, conn: &mut tquic::Connection) {
        info!("server: connection closed: {:?}", conn.index());
    }
    fn on_stream_created(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        info!("server: stream created: {:?} {}", conn.index(), stream_id);
    }
    fn on_stream_readable(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        let mut buf = vec![0u8; 65535];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((len, fin)) => {
                    let data = &buf[..len];
                    if len > 0 {
                        // Echo back
                        match conn.stream_write(stream_id, Bytes::copy_from_slice(data), fin) {
                            Ok(_) => {},
                            Err(tquic::Error::Done) => {},
                            Err(e) => error!("server: stream write error: {}", e),
                        }
                    }
                    if fin {
                        // Connection will be closed by client or eventually
                    }
                }
                Err(tquic::Error::Done) => break,
                Err(tquic::Error::StreamReset(0)) => break,
                Err(e) => {
                    error!("server: stream read error: {}", e);
                    break;
                }
            }
        }
    }
    fn on_stream_writable(&mut self, _conn: &mut tquic::Connection, _stream_id: u64) {}
    fn on_stream_closed(&mut self, _conn: &mut tquic::Connection, _stream_id: u64) {}
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
                error!("server: send packet error: {}", e);
                break;
            }
            sent += 1;
        }
        Ok(sent)
    }
}



#[tokio::test]
async fn test_trojan_tquic() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    
    // 1. Setup certs
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(CERT_PEM.as_bytes()).unwrap();
    let cert_path = cert_file.path().to_str().unwrap().to_owned();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(KEY_PEM.as_bytes()).unwrap();
    let key_path = key_file.path().to_str().unwrap().to_owned();
    
    // 2. Start Server
    let (tx, rx) = std::sync::mpsc::channel();
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
            
        rt.block_on(async {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let port = socket.local_addr().unwrap().port();
            tx.send(port).unwrap();
            
            let mut config = tquic::Config::new().unwrap();
            config.set_max_idle_timeout(30000);
            config.set_initial_max_streams_bidi(100);
            config.set_initial_max_data(10_000_000);
            config.set_initial_max_stream_data_bidi_local(1_000_000);
            config.set_initial_max_stream_data_bidi_remote(1_000_000);
            
            let tls_config = tquic::TlsConfig::new_server_config(
                &cert_path,
                &key_path,
                vec![b"h3".to_vec(), b"http/1.1".to_vec()],
                false,
            ).unwrap();
            
            config.set_tls_config(tls_config);
            
            let handler = Box::new(ServerHandler {});
            let sender = Rc::new(ServerPacketSender { socket: socket.clone() });
            
            let mut endpoint = tquic::Endpoint::new(Box::new(config), true, handler, sender);
            
            let mut buf = vec![0u8; 65535];
            
            loop {
                let timeout = endpoint.timeout();
                 tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        let (len, addr) = res.unwrap();
                        let info = tquic::PacketInfo {
                            src: addr,
                            dst: socket.local_addr().unwrap(),
                            time: Instant::now(),
                        };
                        endpoint.recv(&mut buf[..len], &info).unwrap();
                        endpoint.process_connections().unwrap();
                    }
                    _ = async {
                        if let Some(t) = timeout {
                            tokio::time::sleep(t).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        endpoint.on_timeout(Instant::now());
                        endpoint.process_connections().unwrap();
                    }
                }
            }
        });
    });
    
    let port = rx.recv().unwrap();
    
    // 3. Setup Client
    let tquic_client = Arc::new(TQuicClient::new().unwrap());
    
    let opts = HandlerOptions {
        name: "trojan-tquic".to_string(),
        common_opts: HandlerCommonOptions::default(),
        server: "127.0.0.1".to_string(),
        port,
        password: "password".to_string(),
        udp: false,
        tls: None,
        transport: None,
        quic_client: None,
        tquic_client: Some(tquic_client),
    };

    let client = TrojanOutbound::new(opts);
    
    let resolver = Arc::new(SystemResolver::new(false).unwrap());
    
    // 4. Connect and Test
    // Use resolver to create a dummy stream to the destination
    let sess = Session {
        destination: SocksAddr::try_from(("127.0.0.1".to_string(), 1234)).unwrap(),
        ..Default::default()
    };

    // We can't use connect_stream_with_connector because it's private or not easily accessible if not via trait?
    // connect_stream is public in OutboundHandler trait
    use crate::proxy::OutboundHandler;
    
    let mut stream = client.connect_stream(
        &sess,
        resolver.clone(),
    ).await.expect("failed to connect to trojan tquic server");
    
    // 5. Verify Data
    let payload = b"hello world";
    stream.write_all(payload).await.unwrap();
    
    // Server echoes back [Header][Payload]
    // Header length: 56 (hash) + 2 (CRLF) + 1 (Cmd) + 7 (IPv4 Addr) + 2 (CRLF) = 68 bytes
    // Payload: 11 bytes
    // Total: 79 bytes
    
    let mut buf = vec![0u8; 1024];
    let mut received = Vec::new();
    while received.len() < 68 + 11 {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    
    assert!(received.len() >= 68 + 11, "received only {} bytes", received.len());
    
    let received_payload = &received[68..68+11];
    assert_eq!(received_payload, payload);
}
