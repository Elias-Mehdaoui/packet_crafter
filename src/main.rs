//! # Network Scanner
//!
//! A raw socket network scanner that constructs and sends custom Ethernet, IPv4, and UDP/TCP packets.
//!
//! This tool allows you to manually craft network packets with custom MAC addresses, IP addresses,
//! and Layer 4 protocols for network scanning and testing purposes.
//!
//! ## Usage
//!
//! ```bash
//! # Basic UDP scan
//! cargo run -- --src_ip=192.168.25.2 --dst_ip=192.168.1.25 --dest_port=8080
//!
//! # TCP scan with custom MAC addresses
//! cargo run -- --src_mac=aa:bb:cc:dd:ee:ff --dst_mac=11:22:33:44:55:66 --l4_protocol=tcp
//!
//! # Generate debug output in PCAP format
//! cargo run -- --debug_file=./debug.pcap --debug_format=pcap
//!
//! # Generate debug output in JSON format
//! cargo run -- --debug_file=./debug.json --debug_format=json
//! ```
//!
//! ## Features
//!
//! - Constructs complete Ethernet/IPv4/TCP or UDP packets from scratch
//! - Supports custom MAC addresses for source and destination
//! - Configurable Layer 4 protocol (TCP or UDP)
//! - Optional dry-run mode for testing without sending packets
//! - Debug output in PCAP or JSON format
//! - IPv4 bitfield manipulation for flags/fragmentation offset

use clap::Parser;
use scanner::{Args, DebugFormat, packet::PacketBuilder, output::{write_pcap, write_json}};
use std::path::Path;

/// Main entry point for the network scanner.
///
/// This function:
/// 1. Parses command-line arguments
/// 2. Validates argument consistency
/// 3. Constructs a network packet based on the provided parameters
/// 4. Optionally writes the packet to a debug file (PCAP or JSON format)
///
/// The program exits with status code 0 on success, or non-zero on error.
///
/// # Exit Codes
///
/// - `0`: Success - packet was constructed and optionally written
/// - `1`: Error - validation failed or file write failed
fn main() {
    let args = Args::parse();
    
    if let Err(e) = args.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    
    let mut builder = PacketBuilder::from(&args);
    let payload = b"probe packet";
    let packet = builder.build_packet(payload);
    
    if let (Some(format), Some(file_path)) = (&args.debug_format, &args.debug_file) {
        let path = Path::new(file_path);
        let result = match format {
            DebugFormat::Pcap => write_pcap(path, packet),
            DebugFormat::Json => write_json(path, packet),
        };
        
        if let Err(e) = result {
            eprintln!("Failed to write debug file: {}", e);
            std::process::exit(1);
        }
    }
}
