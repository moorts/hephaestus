use std::io;
use std::{net::SocketAddr, sync::Arc};
use rand::RngCore;

use color_eyre::eyre::Result;

use crate::client::Client;
use crate::payload::Payload;
use quinn::{default_runtime, ClientConfig, Connection, Endpoint, EndpointConfig, PayloadConfig, TransportConfig};
use quinn_proto::ConnectionId;

impl From<Payload> for PayloadConfig {
    fn from(payload: Payload) -> Self {
        match payload {
            Payload::Sirf { scid } => Self::new()
                .with_scid(ConnectionId::new(&scid)),
            Payload::Vnrf { scid, dcid, version: _ } => Self::new()
                .with_scid(ConnectionId::new(&scid))
                .with_dcid(ConnectionId::new(&dcid)),
            Payload::Cmrf { scid, .. } => Self::new()
                .with_scid(ConnectionId::new(&scid)),
        }
    }
}

// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

pub struct QuinnClient {
    endpoint: Endpoint,
    client_crypto: rustls::ClientConfig,
    pub active_connection: Option<Connection>,
}

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3", b"h3-27", b"h3-29"];

impl Client for QuinnClient {
    fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();

        // Write secrets to SSLKEYLOGFILE for wireshark
        client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
        let endpoint = Endpoint::client(addr)?;

        Ok(Self {
            endpoint,
            client_crypto,
            active_connection: None,
        })
    }

    async fn connect(
        &mut self,
        remote: SocketAddr,
        server_name: &str,
        payload: Payload,
    ) -> Result<()> {
        let cfg = TransportConfig::default();
        let mut client_config = ClientConfig::new(Arc::new(self.client_crypto.clone()));

        if let Payload::Vnrf { scid: _, dcid: _, version } = payload {
            client_config.version(version);
        }

        client_config.payload_config(payload.into());
        client_config.transport_config(Arc::new(cfg));

        self.endpoint.set_default_client_config(client_config);

        // Initiate handshake
        let connection = self.endpoint.connect(remote, server_name)?.await?;
        self.active_connection = Some(connection);

        Ok(())
    }
}
