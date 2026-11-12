#![feature(assert_matches)]
mod common;

use std::{assert_matches::assert_matches, net::UdpSocket};

use bytes::BytesMut;
use color_eyre::eyre::Result;

use log::info;
use quinn::TransportConfig;
use quinn_proto::packet::PlainHeader;

use hephaestus_core::{
    payload::Payload,
    clients::QuinnClient,
    network::Harness,
    packets::{extract_quic_header, parse_version_negotiate}, protocol_impersonation::craft_dns_request_payload,
};

#[tokio::test(flavor = "multi_thread")]
/// Send QUIC ClientHello invalid QUIC version identifier and spoofed source address.
///
/// Check that the server responds by sending a version negotiation packet to the target.
async fn version_negotiation_request_forgery() -> Result<()> {
    common::setup();

    let victim_addr = "127.0.0.1:4435".parse().unwrap();
    let target_addr = "127.0.0.1:1234".parse().unwrap();
    let server_endpoint = common::server_endpoint(TransportConfig::default(), victim_addr);

    let payload = craft_dns_request_payload("tu-berlin.de")?;

    let mut harness = Harness::<QuinnClient>::new(victim_addr, target_addr)?;

    // We don't care if this would outlive the runtime.
    let server_fut = tokio::spawn(async move { server_endpoint.accept().await.unwrap().await });

    // Set up dummy target.
    let target = UdpSocket::bind(target_addr)?;

    // Execute VNRF.
    assert!(harness.run(payload.clone()).await.is_ok());

    // Should comfortably fit the header.
    let buf_size = 1300;

    let mut buf = BytesMut::zeroed(buf_size);

    // Receive (first) redirected packet.
    assert_matches!(target.recv_from(&mut buf), Ok((_, source_addr)) if source_addr == victim_addr);

    // Hopefully we actually got a QUIC packet.
    // Also checks if it is a valid version negotiation packet.
    let quic_header = parse_version_negotiate(&buf)?;

    match payload {
        Payload::Vnrf { scid, dcid, version: _ } => {
            info!("{:x?}", parse_version_negotiate(&buf)?);
        },
        _ => unreachable!(),
    }

    Ok(())
}
