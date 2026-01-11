use tracing::warn;
use std::sync::Arc;

const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];
const DEFAULT_WS_ALPN: [&str; 1] = ["http/1.1"];
const DEFAULT_QUIC_ALPN: [&str; 1] = ["h3"];

use crate::{
    Error,
    config::internal::proxy::OutboundTrojan,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcClient, TlsClient, WsClient},
        trojan::{Handler, HandlerOptions, quic::QuicClient, tquic::TQuicClient},
    },
};

impl TryFrom<OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTrojan) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTrojan) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let network = s.network.as_deref();
        let is_quic = matches!(network, Some("quic") | Some("tquic"));

        let tls = if is_quic {
            None
        } else {
            let client = TlsClient::new(
                skip_cert_verify,
                s.sni
                    .as_ref()
                    .map(|x| x.to_owned())
                    .unwrap_or(s.common_opts.server.to_owned()),
                s.alpn.clone().or(Some({
                    let alpn: &[&str] = if let Some("ws") = network {
                        &DEFAULT_WS_ALPN
                    } else {
                        &DEFAULT_ALPN
                    };

                    alpn.iter()
                        .copied()
                        .map(|x| x.to_owned())
                        .collect::<Vec<String>>()
                })),
                None,
            );
            Some(Box::new(client) as _)
        };

        let mut transport = None;
        let mut quic_client = None;
        let mut tquic_client = None;

        if let Some(n) = network {
            match n {
                "ws" => {
                    transport = s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            let client: WsClient = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid ws_opts");
                            Box::new(client) as _
                        })
                        .or(Some(
                            // Return error if ws_opts missing
                            Err(Error::InvalidConfig("ws_opts is required for ws".to_owned()))?,
                        ));
                }
                "grpc" => {
                    transport = s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            let client: GrpcClient =
                                (s.sni.clone(), x, &s.common_opts)
                                    .try_into()
                                    .expect("invalid grpc_opts");
                            Box::new(client) as _
                        })
                        .or(Some(
                             Err(Error::InvalidConfig("grpc_opts is required for grpc".to_owned()))?,
                        ));
                }
                "quic" => {
                    let alpn = s.alpn.clone().unwrap_or_else(|| {
                        DEFAULT_QUIC_ALPN.iter().map(|x| x.to_string()).collect()
                    });
                    
                    let sni = s.sni.clone().unwrap_or(s.common_opts.server.clone());
                    
                    let client = QuicClient::new(
                        s.common_opts.server.clone(),
                        s.common_opts.port,
                        sni,
                        alpn,
                        skip_cert_verify,
                    );
                    quic_client = Some(Arc::new(client));
                }
                "tquic" => {
                    let congestion_controller = s.quic_opts.as_ref().and_then(|x| x.congestion_controller.clone());
                    let client = TQuicClient::new(congestion_controller)
                        .map_err(|e| Error::InvalidConfig(format!("failed to create tquic client: {}", e)))?;
                    tquic_client = Some(Arc::new(client));
                }
                x => {
                    return Err(Error::InvalidConfig(format!(
                        "unsupported trojan network: {x}"
                    )));
                }
            }
        }

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            tls,
            transport,
            quic_client,
            tquic_client,
        });
        Ok(h)
    }
}
