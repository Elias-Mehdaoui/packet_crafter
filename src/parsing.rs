//! Parsing utilities for command-line arguments.
//!
//! This module provides custom parser functions for complex argument types
//! used by the packet crafter, including MAC addresses and bitfield values.

/// Parses a MAC address string into a 6-byte array.
///
/// Accepts MAC addresses in the standard colon-separated format:
/// `aa:bb:cc:dd:ee:ff` where each octet is a two-digit hexadecimal number.
///
/// # Arguments
///
/// * `mac` - A string slice containing the MAC address in colon-separated format
///
/// # Returns
///
/// * `Ok([u8; 6])` - A 6-byte array representing the MAC address
/// * `Err(String)` - An error message if parsing fails
///
/// # Errors
///
/// This function will return an error if:
/// - The input doesn't contain exactly 6 octets
/// - Any octet is not a valid hexadecimal number
///
/// # Examples
///
/// ```rust
/// use packet_crafter::parsing::parse_mac;
///
/// // Valid MAC address
/// let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
/// assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
///
/// // Invalid: too few octets
/// assert!(parse_mac("aa:bb:cc").is_err());
///
/// // Invalid: non-hex characters
/// assert!(parse_mac("xx:yy:zz:aa:bb:cc").is_err());
/// ```
pub fn parse_mac(mac: &str) -> Result<[u8; 6], String> {
    let octets: Vec<&str> = mac.split(|c| c == ':').collect();
    if octets.len() != 6 {
        return Err(format!("Expected 6 octets, got {}", octets.len()));
    }
    let mut bytes = [0u8; 6];
    for (i, octet) in octets.iter().enumerate() {
        match u8::from_str_radix(octet, 16) {
            Ok(b) => bytes[i] = b,
            Err(_) => return Err(format!("Invalid octet: {}", octet)),
        }
    }
    Ok(bytes)
}

/// Parses a bitfield value from a string, supporting both decimal and hexadecimal formats.
///
/// This function is used to parse the `--ip_bitfield` argument which manipulates
/// the IPv4 header's flags and fragment offset fields.
///
/// # Arguments
///
/// * `s` - A string slice containing either a decimal number or a hexadecimal number prefixed with "0x"
///
/// # Returns
///
/// * `Ok(u8)` - The parsed 8-bit value
/// * `Err(String)` - An error message if parsing fails
///
/// # Formats
///
/// - Decimal: `"4"`, `"255"`, `"0"`
/// - Hexadecimal: `"0x04"`, `"0xFF"`, `"0x00"`
///
/// # Examples
///
/// ```rust
/// use packet_crafter::parsing::parse_bitfield;
///
/// // Parse decimal
/// assert_eq!(parse_bitfield("4").unwrap(), 4);
/// assert_eq!(parse_bitfield("255").unwrap(), 255);
///
/// // Parse hexadecimal
/// assert_eq!(parse_bitfield("0x04").unwrap(), 4);
/// assert_eq!(parse_bitfield("0xFF").unwrap(), 255);
/// assert_eq!(parse_bitfield("0x00").unwrap(), 0);
///
/// // Invalid values
/// assert!(parse_bitfield("256").is_err());  // Too large
/// assert!(parse_bitfield("0xGG").is_err()); // Invalid hex
/// ```
pub fn parse_bitfield(s: &str) -> Result<u8, String> {
    let (input, radix) = if let Some(hex_str) = s.strip_prefix("0x") {
        (hex_str, 16)
    } else {
        (s, 10)
    };
    match u8::from_str_radix(input, radix) {
        Ok(value) => Ok(value),
        Err(_) => {
            if radix == 16 {
                Err(format!("Invalid hex value: {}", s))
            } else {
                Err(format!("Invalid decimal value: {}", s))
            }
        }
    }
}


