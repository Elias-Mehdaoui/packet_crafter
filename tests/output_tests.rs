//! Tests for output functionality (PCAP and JSON writing)

use scanner::{Args, L4Protocol, packet::PacketBuilder, output::{write_pcap, write_json}, parsing};
use std::fs;
use tempfile::TempDir;
use pcap_file::pcap::PcapReader;

fn create_test_args() -> Args {
    Args {
        src_ip: "192.168.1.1".parse().unwrap(),
        dst_ip: "192.168.1.2".parse().unwrap(),
        dest_port: 80,
        src_mac: parsing::parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
        dst_mac: parsing::parse_mac("11:22:33:44:55:66").unwrap(),
        l4_protocol: L4Protocol::Udp,
        timeout_ms: 1000,
        debug_file: None,
        debug_format: None,
        ip_bitfield: 0,
    }
}

// ==================== PCAP Output Tests ====================

#[test]
fn test_write_pcap_creates_valid_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.pcap");
    
    let args = create_test_args();
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"test packet");
    
    let result = write_pcap(&file_path, packet);
    assert!(result.is_ok(), "PCAP write should succeed");
    assert!(file_path.exists(), "PCAP file should exist");
    
    // Verify it's a valid PCAP file
    let file = fs::File::open(&file_path).unwrap();
    let pcap_reader = PcapReader::new(file);
    assert!(pcap_reader.is_ok(), "PCAP file should be valid");
}

#[test]
fn test_write_pcap_contains_packet_data() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.pcap");
    
    let args = create_test_args();
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"test");
    let packet_len = packet.len();
    
    write_pcap(&file_path, packet).unwrap();
    
    // Read and verify
    let file = fs::File::open(&file_path).unwrap();
    let mut pcap_reader = PcapReader::new(file).unwrap();
    let captured = pcap_reader.next_packet().unwrap().unwrap();
    
    assert_eq!(captured.data.len(), packet_len);
}

// ==================== JSON Output Tests ====================

#[test]
fn test_write_json_creates_valid_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.json");
    
    let args = create_test_args();
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"test packet");
    
    let result = write_json(&file_path, packet);
    assert!(result.is_ok(), "JSON write should succeed");
    assert!(file_path.exists(), "JSON file should exist");
    
    // Verify it's valid JSON with correct structure
    let content = fs::read_to_string(&file_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    
    assert!(json["timestamp"].is_f64(), "Should have timestamp");
    assert!(json["length"].is_u64(), "Should have length");
    assert!(json["data"].is_string(), "Should have hex data");
}

#[test]
fn test_write_json_correct_data() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.json");
    
    let args = create_test_args();
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"test");
    let expected_hex = hex::encode(packet);
    let expected_len = packet.len();
    
    write_json(&file_path, packet).unwrap();
    
    let content = fs::read_to_string(&file_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    
    assert_eq!(json["length"].as_u64().unwrap(), expected_len as u64);
    assert_eq!(json["data"].as_str().unwrap(), expected_hex);
}

// ==================== Protocol Tests ====================

#[test]
fn test_write_tcp_packet_to_pcap() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("tcp.pcap");
    
    let mut args = create_test_args();
    args.l4_protocol = L4Protocol::Tcp;
    
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"TCP test");
    
    let result = write_pcap(&file_path, packet);
    assert!(result.is_ok(), "Should write TCP packet to PCAP");
}

#[test]
fn test_write_tcp_packet_to_json() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("tcp.json");
    
    let mut args = create_test_args();
    args.l4_protocol = L4Protocol::Tcp;
    
    let mut builder = PacketBuilder::from(&args);
    let packet = builder.build_packet(b"TCP test");
    
    let result = write_json(&file_path, packet);
    assert!(result.is_ok(), "Should write TCP packet to JSON");
}
