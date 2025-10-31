//! Packet construction module for building raw network packets.
//!
//! This module provides the `PacketBuilder` struct which constructs complete
//! Ethernet/IPv4/TCP or UDP packets from scratch, with proper checksums and
//! all protocol headers correctly formatted.

use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::ipv4::{MutableIpv4Packet, checksum as ipv4_checksum};
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use std::net::Ipv4Addr;

use crate::{Args, L4Protocol};

/// Packet builder for constructing raw network packets.
///
/// This struct provides methods to build complete Ethernet frames with IPv4 and
/// TCP/UDP packets.

/// Builder for constructing raw network packets.
///
/// `PacketBuilder` creates complete network packets including Ethernet (L2),
/// IPv4 (L3), and TCP/UDP (L4) headers.
///
/// # Packet Structure
///
/// The constructed packets follow this structure:
/// ```text
/// +----------------+
/// | Ethernet (14B) |  Layer 2: MAC addresses, EtherType
/// +----------------+
/// | IPv4 (20B)     |  Layer 3: IP addresses, protocol
/// +----------------+
/// | TCP/UDP        |  Layer 4: Ports, checksums
/// | (20B / 8B)     |
/// +----------------+
/// | Payload        |  Application data
/// +----------------+
/// ```
pub struct PacketBuilder {
    /// Source IPv4 address
    src_ip: Ipv4Addr,
    /// Destination IPv4 address
    dst_ip: Ipv4Addr,
    /// Destination port number (TCP/UDP)
    dest_port: u16,
    /// Source MAC address (Ethernet layer)
    src_mac: [u8; 6],
    /// Destination MAC address (Ethernet layer)
    dst_mac: [u8; 6],
    /// Layer 4 protocol (TCP or UDP)
    l4_protocol: L4Protocol,
    /// IPv4 header flags/fragment offset bitfield
    ip_bitfield: u8,
    /// Internal buffer for packet construction (1500 bytes for standard MTU)
    buffer: Vec<u8>,
}

/// Converts command-line arguments into a `PacketBuilder`.
///
/// Creates a new `PacketBuilder` initialized with all parameters from the
/// parsed command-line arguments. The internal buffer is pre-allocated
/// with 1500 bytes (standard Ethernet MTU).
impl From<&Args> for PacketBuilder {
    fn from(args: &Args) -> Self {
        Self {
            src_ip: args.src_ip,
            dst_ip: args.dst_ip,
            dest_port: args.dest_port,
            src_mac: args.src_mac,
            dst_mac: args.dst_mac,
            l4_protocol: args.l4_protocol.clone(),
            ip_bitfield: args.ip_bitfield,
            buffer: vec![0u8; 1500],
        }
    }
}

impl PacketBuilder {
    /// Builds a complete network packet with the given payload.
    ///
    /// Constructs a full packet including Ethernet, IPv4, and TCP/UDP headers
    /// based on the configured protocol. All checksums are computed correctly.
    ///
    /// # Arguments
    ///
    /// * `payload` - The application-layer data to include in the packet
    ///
    /// # Returns
    ///
    /// A byte slice containing the complete packet ready for transmission.
    /// The slice references the internal buffer and is only valid until the
    /// next call to `build_packet`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use packet_crafter::{Args, packet::PacketBuilder};
    /// use clap::Parser;
    ///
    /// # let args = Args::parse();
    /// let mut builder = PacketBuilder::from(&args);
    /// let probe_data = b"Hello, network!";
    /// let packet = builder.build_packet(probe_data);
    ///
    /// // packet now contains: Ethernet + IPv4 + TCP/UDP + probe_data
    /// ```
    pub fn build_packet(&mut self, payload: &[u8]) -> &[u8] {
        match self.l4_protocol {
            L4Protocol::Udp => self.build_udp(payload),
            L4Protocol::Tcp => self.build_tcp(payload),
        }
    }

    /// Constructs a UDP packet with the given payload.
    ///
    /// Builds a complete packet with:
    /// - Ethernet header (14 bytes)
    /// - IPv4 header (20 bytes)
    /// - UDP header (8 bytes)
    /// - Payload
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to include in the UDP packet
    ///
    /// # Returns
    ///
    /// A byte slice containing the complete UDP packet.
    fn build_udp(&mut self, payload: &[u8]) -> &[u8] {
        let total_length = 14 + 20 + 8 + payload.len();
        
        self.build_ethernet_header(total_length);
        self.build_ipv4_header(total_length, IpNextHeaderProtocols::Udp, 8 + payload.len());

        let mut udp_packet = MutableUdpPacket::new(&mut self.buffer[34..total_length]).expect("Failed to create UDP packet");
        udp_packet.set_source(12345);
        udp_packet.set_destination(self.dest_port);
        udp_packet.set_length((8 + payload.len()) as u16);
        udp_packet.set_payload(payload);
        
        let checksum = pnet::packet::udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            &self.src_ip,
            &self.dst_ip,
        );
        udp_packet.set_checksum(checksum);

        &self.buffer[..total_length]
    }

    /// Constructs a TCP packet with the given payload.
    ///
    /// Builds a complete packet with:
    /// - Ethernet header (14 bytes)
    /// - IPv4 header (20 bytes)
    /// - TCP header (20 bytes, no options)
    /// - Payload
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to include in the TCP packet
    ///
    /// # Returns
    ///
    /// A byte slice containing the complete TCP packet.
    fn build_tcp(&mut self, payload: &[u8]) -> &[u8] {
        let total_length = 14 + 20 + 20 + payload.len();
        
        self.build_ethernet_header(total_length);
        self.build_ipv4_header(total_length, IpNextHeaderProtocols::Tcp, 20 + payload.len());

        let mut tcp_packet = MutableTcpPacket::new(&mut self.buffer[34..total_length])
            .expect("Failed to create TCP packet");
        tcp_packet.set_source(12345);
        tcp_packet.set_destination(self.dest_port);
        tcp_packet.set_sequence(0);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(0x02);
        tcp_packet.set_window(64240);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_payload(payload);
        
        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &self.src_ip,
            &self.dst_ip,
        );
        tcp_packet.set_checksum(checksum);

        &self.buffer[..total_length]
    }

    /// Constructs the Ethernet (Layer 2) header.
    ///
    /// Sets up the Ethernet frame with:
    /// - Destination MAC address
    /// - Source MAC address
    /// - EtherType = 0x0800 (IPv4)
    ///
    /// # Arguments
    ///
    /// * `total_length` - Total packet length including all headers and payload
    fn build_ethernet_header(&mut self, total_length: usize) {
        let mut eth_packet = MutableEthernetPacket::new(&mut self.buffer[..total_length])
            .expect("Failed to create Ethernet packet");
        eth_packet.set_destination(self.dst_mac.into());
        eth_packet.set_source(self.src_mac.into());
        eth_packet.set_ethertype(EtherTypes::Ipv4);
    }

    /// Constructs the IPv4 (Layer 3) header.
    ///
    /// Sets up the IPv4 header with:
    /// - Version = 4
    /// - Header length = 5 (20 bytes, no options)
    /// - DSCP/ECN = 0
    /// - Total length = IP header + payload
    /// - Identification = 0
    /// - Flags and fragment offset from `ip_bitfield`
    /// - TTL = 64
    /// - Protocol (TCP or UDP)
    /// - Source and destination IP addresses
    /// - Correct header checksum
    ///
    /// # Arguments
    ///
    /// * `total_length` - Total packet length including Ethernet header
    /// * `protocol` - Next-level protocol (TCP or UDP)
    /// * `payload_length` - Length of Layer 4 header + data
    fn build_ipv4_header(
        &mut self,
        total_length: usize,
        protocol: IpNextHeaderProtocol,
        payload_length: usize,
    ) {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut self.buffer[14..total_length])
            .expect("Failed to create IPv4 packet");
        
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_dscp(0);
        ipv4_packet.set_ecn(0);
        ipv4_packet.set_total_length((20 + payload_length) as u16);
        ipv4_packet.set_identification(0);
        ipv4_packet.set_flags(self.ip_bitfield >> 5);
        ipv4_packet.set_fragment_offset((self.ip_bitfield as u16 & 0x1F) << 8);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(protocol);
        ipv4_packet.set_source(self.src_ip);
        ipv4_packet.set_destination(self.dst_ip);
        
        let checksum = ipv4_checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
    }
}
