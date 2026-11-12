#![feature(assert_matches)]
mod common;

use std::{assert_matches::assert_matches, net::UdpSocket};

use bytes::BytesMut;
use color_eyre::eyre::Result;

use quinn::TransportConfig;
use quinn_proto::packet::PlainHeader;

use hephaestus_core::{
    clients::QuinnClient, network::Harness, packets::{extract_quic_header, parse_version_negotiate}, payload::Payload
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

    let scid = vec![2; 255];
    let dcid = vec![3; 255];
    let payload = Payload::Vnrf {
        // Bigger connection ids allowed for unknwon versions.
        scid: scid.clone(),
        dcid: dcid.clone(),
        // Use invalid version number to trigger version negotiation.
        version: 0x1337_1337,
    };

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
    // let quic_header = extract_quic_header(&buf)?;
    let quic_packet = parse_version_negotiate(&buf)?;

    // Assert that the target actually got a version negotiate packet from the server.
    // Also ensure that both CIDs are preserved.
    assert_eq!(quic_packet.scid, dcid);
    assert_eq!(quic_packet.dcid, scid);

    println!("{:?}", quic_packet);

    Ok(())
}
