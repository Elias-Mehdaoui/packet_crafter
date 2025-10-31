//! Tests for command-line argument validation

use scanner::Args;

#[test]
fn test_validation_both_format_and_file() {
    let args = Args {
        src_ip: "192.168.0.1".parse().unwrap(),
        dst_ip: "192.168.0.2".parse().unwrap(),
        dest_port: 80,
        src_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        dst_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        l4_protocol: scanner::L4Protocol::Udp,
        timeout_ms: 1000,
        debug_file: Some("test.json".to_string()),
        debug_format: Some(scanner::DebugFormat::Json),
        ip_bitfield: 0,
    };
    
    assert!(args.validate().is_ok(), "Valid args should pass validation");
}

#[test]
fn test_validation_neither_format_nor_file() {
    let args = Args {
        src_ip: "192.168.0.1".parse().unwrap(),
        dst_ip: "192.168.0.2".parse().unwrap(),
        dest_port: 80,
        src_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        dst_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        l4_protocol: scanner::L4Protocol::Udp,
        timeout_ms: 1000,
        debug_file: None,
        debug_format: None,
        ip_bitfield: 0,
    };
    
    assert!(args.validate().is_ok(), "No debug output should be valid");
}

#[test]
fn test_validation_format_without_file() {
    let args = Args {
        src_ip: "192.168.0.1".parse().unwrap(),
        dst_ip: "192.168.0.2".parse().unwrap(),
        dest_port: 80,
        src_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        dst_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        l4_protocol: scanner::L4Protocol::Udp,
        timeout_ms: 1000,
        debug_file: None,
        debug_format: Some(scanner::DebugFormat::Json),
        ip_bitfield: 0,
    };
    
    assert!(args.validate().is_err(), "Format without file should fail");
}

#[test]
fn test_validation_file_without_format() {
    let args = Args {
        src_ip: "192.168.0.1".parse().unwrap(),
        dst_ip: "192.168.0.2".parse().unwrap(),
        dest_port: 80,
        src_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        dst_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        l4_protocol: scanner::L4Protocol::Udp,
        timeout_ms: 1000,
        debug_file: Some("test.json".to_string()),
        debug_format: None,
        ip_bitfield: 0,
    };
    
    assert!(args.validate().is_err(), "File without format should fail");
}

#[test]
fn test_validation_extension_mismatch() {
    let args = Args {
        src_ip: "192.168.0.1".parse().unwrap(),
        dst_ip: "192.168.0.2".parse().unwrap(),
        dest_port: 80,
        src_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        dst_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        l4_protocol: scanner::L4Protocol::Udp,
        timeout_ms: 1000,
        debug_file: Some("test.pcap".to_string()),
        debug_format: Some(scanner::DebugFormat::Json),
        ip_bitfield: 0,
    };
    
    assert!(args.validate().is_err(), "Format/extension mismatch should fail");
}

#[test]
fn test_validation_pcap_format() {
    let args = Args {
        src_ip: "192.168.0.1".parse().unwrap(),
        dst_ip: "192.168.0.2".parse().unwrap(),
        dest_port: 80,
        src_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        dst_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        l4_protocol: scanner::L4Protocol::Udp,
        timeout_ms: 1000,
        debug_file: Some("test.pcap".to_string()),
        debug_format: Some(scanner::DebugFormat::Pcap),
        ip_bitfield: 0,
    };
    
    assert!(args.validate().is_ok(), "PCAP format with .pcap extension should be valid");
}

