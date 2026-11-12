use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Endpoint, TransportConfig};
use simplelog::*;

use hephaestus_core::network::DEFAULT_SERVER_NAME;

/// !!!Only call this once per integration test file!!!
///
/// Sets up logging, error handling and escalates priviledges if necessary.
/// 
/// Escalating priviledges restarts the process, so stuff gets weird if called multiple times.
/// E.g., port clashes when multiple servers are started.
pub fn setup() {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();
    color_eyre::install().expect("Failed to initialize error handler.");
    sudo::escalate_if_needed().expect("Invalid priviledges.");
}

/// Create a QUIC server listening on `server_addr`.
pub fn server_endpoint(transport_config: TransportConfig, server_addr: SocketAddr) -> Endpoint {
    // Generate some certificate that we won't use.
    // TODO: Make this work without generating them.
    let cert = rcgen::generate_simple_self_signed(vec![DEFAULT_SERVER_NAME.into()]).unwrap();
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert = rustls::Certificate(cert.serialize_der().unwrap());

    let mut roots = rustls::RootCertStore::empty();
    roots.add(&cert).unwrap();

    let transport_config = Arc::new(transport_config);

    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
    server_config.transport_config(transport_config);

    Endpoint::server(server_config, server_addr).unwrap()
}
