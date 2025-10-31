//! Tests for packet construction
//!
//! Verifies that PacketBuilder correctly constructs Ethernet/IPv4/TCP/UDP packets.

use packet_crafter::{Args, L4Protocol, packet::PacketBuilder, parsing};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

fn create_test_args(protocol: L4Protocol) -> Args {
    Args {
        src_ip: "192.168.0.1".parse().unwrap(),
        dst_ip: "192.168.0.2".parse().unwrap(),
        dest_port: 80,
        src_mac: parsing::parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
        dst_mac: parsing::parse_mac("11:22:33:44:55:66").unwrap(),
        l4_protocol: protocol,
        timeout_ms: 1000,
        debug_file: None,
        debug_format: None,
        ip_bitfield: 0,
    }
}

// ==================== UDP Packet Tests ====================

#[test]
fn test_udp_packet_construction() {
    let args = create_test_args(L4Protocol::Udp);
    let mut builder = PacketBuilder::from(&args);
    let payload = b"test payload";
    let packet = builder.build_packet(payload);
    
    // Verify Ethernet header
    let eth = EthernetPacket::new(packet).unwrap();
    assert_eq!(eth.get_source().octets(), args.src_mac);
    assert_eq!(eth.get_destination().octets(), args.dst_mac);
    assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);
    
    // Verify IPv4 header
    let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
    assert_eq!(ipv4.get_version(), 4);
    assert_eq!(ipv4.get_source(), args.src_ip);
    assert_eq!(ipv4.get_destination(), args.dst_ip);
    assert_eq!(ipv4.get_next_level_protocol().0, 17); // UDP
    
    // Verify UDP header and payload
    let udp = UdpPacket::new(ipv4.payload()).unwrap();
    assert_eq!(udp.get_destination(), args.dest_port);
    assert_eq!(udp.payload(), payload);
}

#[test]
fn test_udp_checksums() {
    let args = create_test_args(L4Protocol::Udp);
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"test");
    
    let eth = EthernetPacket::new(packet).unwrap();
    let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
    let udp = UdpPacket::new(ipv4.payload()).unwrap();
    
    assert_ne!(ipv4.get_checksum(), 0, "IPv4 checksum should be set");
    assert_ne!(udp.get_checksum(), 0, "UDP checksum should be set");
}

// ==================== TCP Packet Tests ====================

#[test]
fn test_tcp_packet_construction() {
    let args = create_test_args(L4Protocol::Tcp);
    let mut builder = PacketBuilder::from(&args);
    let payload = b"test payload";
    let packet = builder.build_packet(payload);
    
    // Verify Ethernet header
    let eth = EthernetPacket::new(packet).unwrap();
    assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);
    
    // Verify IPv4 header
    let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
    assert_eq!(ipv4.get_next_level_protocol().0, 6); // TCP
    
    // Verify TCP header and payload
    let tcp = TcpPacket::new(ipv4.payload()).unwrap();
    assert_eq!(tcp.get_destination(), args.dest_port);
    assert_eq!(tcp.get_flags(), 0x02); // SYN flag
    assert_eq!(tcp.payload(), payload);
}

#[test]
fn test_tcp_checksums() {
    let args = create_test_args(L4Protocol::Tcp);
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"test");
    
    let eth = EthernetPacket::new(packet).unwrap();
    let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
    let tcp = TcpPacket::new(ipv4.payload()).unwrap();
    
    assert_ne!(ipv4.get_checksum(), 0, "IPv4 checksum should be set");
    assert_ne!(tcp.get_checksum(), 0, "TCP checksum should be set");
}

// ==================== IP Bitfield Tests ====================

#[test]
fn test_ip_bitfield_flags() {
    let mut args = create_test_args(L4Protocol::Udp);
    args.ip_bitfield = 0x40; // Don't Fragment flag
    
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"test");
    
    let eth = EthernetPacket::new(packet).unwrap();
    let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
    
    // Top 3 bits of bitfield become flags (0x40 >> 5 = 2 = Don't Fragment)
    assert_eq!(ipv4.get_flags(), 2);
}

// ==================== Edge Cases ====================

#[test]
fn test_custom_addresses_and_ports() {
    let mut args = create_test_args(L4Protocol::Udp);
    args.src_ip = "10.0.0.1".parse().unwrap();
    args.dst_ip = "8.8.8.8".parse().unwrap();
    args.dest_port = 443;
    args.src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    args.dst_mac = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"test");
    
    let eth = EthernetPacket::new(packet).unwrap();
    assert_eq!(eth.get_source().octets(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(eth.get_destination().octets(), [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]);
    
    let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
    assert_eq!(ipv4.get_source().to_string(), "10.0.0.1");
    assert_eq!(ipv4.get_destination().to_string(), "8.8.8.8");
    
    let udp = UdpPacket::new(ipv4.payload()).unwrap();
    assert_eq!(udp.get_destination(), 443);
}

#[test]
fn test_empty_payload() {
    let args = create_test_args(L4Protocol::Udp);
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"");
    
    assert!(!packet.is_empty(), "Packet with empty payload should still have headers");
    
    let eth = EthernetPacket::new(packet).unwrap();
    let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
    let udp = UdpPacket::new(ipv4.payload()).unwrap();
    assert_eq!(udp.payload().len(), 0);
}
