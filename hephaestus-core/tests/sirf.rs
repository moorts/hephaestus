#![feature(assert_matches)]

mod common;

use std::{assert_matches::assert_matches, net::UdpSocket};

use log::info;
use bytes::BytesMut;
use quinn::TransportConfig;

use color_eyre::eyre::Result;

use hephaestus_core::{
    payload::Payload,
    clients::QuinnClient,
    network::{Harness, PacketFilter}, packets::{extract_quic_header, quic_header_from_ethernet},
};

/// Send QUIC ClientHello with spoofed source address and check if the server sends the response to
/// the target.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn server_initial_request_forgery() -> Result<()> {
    common::setup();

    let victim_addr = "[::1]:4435".parse().unwrap();
    let target_addr = "[::1]:1234".parse().unwrap();
    let server_endpoint = common::server_endpoint(TransportConfig::default(), victim_addr);

    let scid = vec![2; 20];
    let payload = Payload::Sirf {
        scid: scid.clone(),
    };

    let mut harness = Harness::<QuinnClient>::new(victim_addr, target_addr)?;

    // We don't care if this would outlive the runtime.
    let server_handle = tokio::spawn(async move { server_endpoint.accept().await.unwrap().await });

    // Open a UPD socket on `target_addr`
    let target = UdpSocket::bind(target_addr)?;

    assert!(harness.run(payload.clone()).await.is_ok());

    // Should comfortably fit the header.
    let buf_size = 1300;

    let mut buf = BytesMut::zeroed(buf_size);

    // Check if there is an incoming packet.
    assert_matches!(target.recv_from(&mut buf), Ok((_, source_addr)) if source_addr == victim_addr);

    let quic_header = extract_quic_header(&buf)?;

    // Check that our scid got preserved.
    assert_eq!(scid, quic_header.dcid);
    Ok(())
}
