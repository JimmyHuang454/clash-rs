use std::{
    io::Write,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use clash_lib::{Config, Options, start_scaffold, shutdown};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, TcpListener, UdpSocket},
};
use tracing::{error, info};
use tempfile::NamedTempFile;

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

#[tokio::test]
#[serial_test::serial]
async fn test_trojan_tquic_yaml_integration() {
    clash_lib::setup_default_crypto_provider();
    
    // 1. Setup certs
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(CERT_PEM.as_bytes()).unwrap();
    let cert_path = cert_file.path().to_str().unwrap().to_owned();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(KEY_PEM.as_bytes()).unwrap();
    let key_path = key_file.path().to_str().unwrap().to_owned();
    
    // 2. Setup Ports
    let mixed_port = 20001;
    let trojan_port = 20002;
    let echo_port = 20003;

    // 3. Start Echo Server (Target)
    tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", echo_port)).await.unwrap();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n == 0 => return,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    if socket.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    // 4. Create Config
    // Inbound: Mixed on mixed_port
    // Inbound: Trojan on trojan_port (network: tquic)
    // Outbound: Trojan to trojan_port (network: tquic)
    let config_yaml = format!(r#"
port: 18888
socks-port: 18889
mixed-port: {mixed_port}
allow-lan: false
mode: rule
log-level: debug
external-controller: :19090

listeners:
  - name: "trojan-in"
    type: trojan
    port: {trojan_port}
    listen: 0.0.0.0
    password: password
    certificate: {cert_path}
    private-key: {key_path}
    network: tquic
    alpn:
      - h3

proxies:
  - name: "trojan-out"
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: password
    udp: true
    network: tquic
    skip-cert-verify: true
    alpn:
      - h3

rules:
  - SRC-IP-CIDR,0.0.0.0/32,DIRECT
  - MATCH,trojan-out
"#);

    // 5. Start Clash
    std::thread::spawn(move || {
        start_scaffold(Options {
            config: Config::Str(config_yaml),
            cwd: None,
            rt: None,
            log_file: None,
        })
        .expect("Failed to start clash");
    });

    // Wait for clash to start
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 6. Connect to Mixed Port and Test
    let proxy_addr = format!("127.0.0.1:{mixed_port}");
    let mut stream = TcpStream::connect(&proxy_addr).await.expect("Failed to connect to proxy");

    // HTTP CONNECT handshake
    let target = format!("127.0.0.1:{}", echo_port);
    let req = format!("CONNECT {} HTTP/1.1\r\n\r\n", target);
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200"), "Proxy handshake failed: {}", resp);

    // 7. Send Data
    let payload = b"hello integration";
    stream.write_all(payload).await.unwrap();

    // 8. Read Echo
    let mut received = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
        if received.len() >= payload.len() {
            break;
        }
    }

    assert_eq!(&received, payload);
    
    shutdown();
}
