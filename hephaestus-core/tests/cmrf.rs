#![feature(assert_matches)]

mod common;

use std::{assert_matches::assert_matches, net::{SocketAddr, UdpSocket}};

use log::info;
use bytes::{Bytes, BytesMut};
use quinn::TransportConfig;

use color_eyre::eyre::{eyre, Context, Result};

use hephaestus_core::{
    client::Client, clients::QuinnClient, network::{Harness, PacketFilter}, packets::{extract_quic_header, quic_header_from_ethernet, spoof_packet}, payload::Payload
};

use std::env;

/// Send QUIC ClientHello with spoofed source address and check if the server sends the response to
/// the target.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn server_initial_request_forgery() -> Result<()> {
    common::setup();

    // Setup key file
    env::set_var("SSLKEYLOGFILE", "./keylog");

    let server_addr = "[::1]:5002".parse().unwrap();
    let client_addr: SocketAddr = "[::1]:5001".parse().unwrap();
    let target_addr = "[::1]:5555".parse().unwrap();


    // let mut filter = PacketFilter::new(client_addr.is_ipv6())?;

    // filter.clear()?;

    // let mut client = QuinnClient::new(client_addr)?;
    let mut harness = Harness::<QuinnClient>::new(server_addr, target_addr)?;
    let server_endpoint = common::server_endpoint(TransportConfig::default(),server_addr);

    let server_handle = tokio::spawn(async move { server_endpoint.accept().await.unwrap().await });

    let target = UdpSocket::bind(target_addr)?;

    let payload = Payload::Cmrf {
        scid: vec![2; 20],
    };

    // let mut nfq = filter.redirect_to(server_addr, 1)?;

    /*
    let attack_fut = tokio::spawn(async move {
        // Retrieve captured message from netfilterqueue
        let mut packet_count = 0;
        loop {
            let mut msg = nfq.recv()
                .map_err(|err| eyre!("{err}").wrap_err("Error receiving packet from netfilterqueue.")).unwrap();

            packet_count += 1;

            info!("Received packet");

            if packet_count > 8 {
                // Handshake Over
                // Overwrite source address and port
                spoof_packet(msg.get_payload_mut(), target_addr).wrap_err("Failed to spoof packet.").unwrap();

            }

            // Forward message to victim
            msg.set_verdict(nfq::Verdict::Accept);
            nfq.verdict(msg).unwrap();

            info!("Sent spoofed packet to victim.");
        }
    });
    */


    // client.connect(server_addr, "localhost", payload).await?;

    // let connection = client.active_connection.unwrap();
    // connection.send_datagram(Bytes::from("hello"))?;
    assert!(harness.run(payload.clone()).await.is_ok());

 
    // Should comfortably fit the header.
    let buf_size = 1300;

    let mut buf = BytesMut::zeroed(buf_size);
    // let msg = target.recv_from(&mut buf)?;

    Ok(())
}
