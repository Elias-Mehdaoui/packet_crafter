//! Tests for parsing utilities
//!
//! Validates MAC address and bitfield parsing functionality.

use packet_crafter::parsing::{parse_mac, parse_bitfield};

// ==================== MAC Address Parsing ====================

#[test]
fn test_parse_mac_valid() {
    let result = parse_mac("aa:bb:cc:dd:ee:ff");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
}

#[test]
fn test_parse_mac_case_insensitive() {
    assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF").unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(parse_mac("Aa:Bb:Cc:Dd:Ee:Ff").unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
}

#[test]
fn test_parse_mac_invalid_length() {
    assert!(parse_mac("aa:bb:cc:dd:ee").is_err());
    assert!(parse_mac("aa:bb:cc:dd:ee:ff:00").is_err());
}

#[test]
fn test_parse_mac_invalid_hex() {
    assert!(parse_mac("aa:bb:cc:dd:ee:gg").is_err());
    assert!(parse_mac("zz:bb:cc:dd:ee:ff").is_err());
}

// ==================== Bitfield Parsing ====================

#[test]
fn test_parse_bitfield_decimal() {
    assert_eq!(parse_bitfield("0").unwrap(), 0);
    assert_eq!(parse_bitfield("4").unwrap(), 4);
    assert_eq!(parse_bitfield("255").unwrap(), 255);
}

#[test]
fn test_parse_bitfield_hex() {
    assert_eq!(parse_bitfield("0x00").unwrap(), 0);
    assert_eq!(parse_bitfield("0x04").unwrap(), 4);
    assert_eq!(parse_bitfield("0xff").unwrap(), 255);
    assert_eq!(parse_bitfield("0xFF").unwrap(), 255);
}

#[test]
fn test_parse_bitfield_invalid() {
    assert!(parse_bitfield("256").is_err());
    assert!(parse_bitfield("0x100").is_err());
    assert!(parse_bitfield("abc").is_err());
    assert!(parse_bitfield("0xGG").is_err());
}

