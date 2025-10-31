//! Output formatting and file writing for debug modes.
//!
//! This module provides functions to write constructed packets to files
//! in two formats: PCAP (for Wireshark analysis) and JSON (for structured
//! inspection).

use pcap_file::pcap::{PcapHeader, PcapWriter, PcapPacket};
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Structured packet information for JSON output.
///
/// Contains metadata and hex-encoded packet data suitable for
/// machine-readable inspection and debugging.
#[derive(Serialize, Deserialize, Debug)]
struct PacketInfo {
    /// Unix timestamp (seconds since epoch) as floating point
    timestamp: f64,
    /// Total packet length in bytes
    length: usize,
    /// Hex-encoded packet data (e.g., "aabbccdd...")
    data: String,
}

/// Writes a packet to a PCAP file.
///
/// Creates a PCAP file compatible with Wireshark/tshark for network analysis.
/// The file is written with:
/// - Datalink type: Ethernet
/// - Endianness: Big-endian
/// - Current timestamp
///
/// # Arguments
///
/// * `path` - The file path where the PCAP file will be created
/// * `packet` - The complete packet bytes (Ethernet frame)
///
/// # Returns
///
/// - `Ok(())` on success
/// - `Err(Box<dyn std::error::Error>)` if file creation or writing fails
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use packet_crafter::output::write_pcap;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let packet = vec![0xaa, 0xbb, 0xcc /* ... packet data ... */];
/// write_pcap(Path::new("debug.pcap"), &packet)?;
/// # Ok(())
/// # }
/// ```
pub fn write_pcap(path: &Path, packet: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    
    let pcap_header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        endianness: pcap_file::Endianness::Big,
        ..Default::default()
    };
    
    let mut pcap_writer = PcapWriter::with_header(file, pcap_header)?;
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    
    let pcap_packet = PcapPacket {
        timestamp: now,
        orig_len: packet.len() as u32,
        data: packet.into(),
    };
    
    pcap_writer.write_packet(&pcap_packet)?;
    
    Ok(())
}

/// Writes a packet to a JSON file with metadata.
///
/// Creates a JSON file containing:
/// - `timestamp`: Unix timestamp as floating-point seconds
/// - `length`: Total packet size in bytes
/// - `data`: Hex-encoded packet data
///
/// The JSON is formatted with pretty printing for readability.
///
/// # Arguments
///
/// * `path` - The file path where the JSON file will be created
/// * `packet` - The complete packet bytes (Ethernet frame)
///
/// # Returns
///
/// - `Ok(())` on success
/// - `Err(Box<dyn std::error::Error>)` if file creation or writing fails
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use packet_crafter::output::write_json;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let packet = vec![0xaa, 0xbb, 0xcc, 0xdd];
/// write_json(Path::new("debug.json"), &packet)?;
/// # Ok(())
/// # }
/// ```
pub fn write_json(path: &Path, packet: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    
    let packet_info = PacketInfo {
        timestamp: now.as_secs_f64(),
        length: packet.len(),
        data: hex::encode(packet),
    };
    
    let json = serde_json::to_string_pretty(&packet_info)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    
    Ok(())
}
