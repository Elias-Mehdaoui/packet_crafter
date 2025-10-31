//! Library module exposing internal components for testing

pub mod parsing;
pub mod packet;
pub mod output;

pub use clap::Parser;
use clap::ValueEnum;
use std::net::Ipv4Addr;
use std::path::Path;

/// Layer 4 (transport layer) protocol options for packet construction.
#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum L4Protocol {
    /// Transmission Control Protocol - connection-oriented, reliable
    Tcp,
    /// User Datagram Protocol - connectionless, best-effort delivery
    Udp,
}

/// Output format for debug files.
#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum DebugFormat {
    /// JSON format with packet metadata and hex-encoded data
    Json,
    /// PCAP format readable by Wireshark/tshark
    Pcap,
}

/// Command-line arguments for the network scanner.
#[derive(Parser, Debug)]
#[command(about = "Network Scanner")]
pub struct Args {
    /// Source IPv4 address to place in the IP header.
    #[arg(long = "src_ip", default_value = "192.168.0.1")]
    pub src_ip: Ipv4Addr,

    /// Destination IPv4 address to place in the IP header.
    #[arg(long = "dst_ip", default_value = "192.168.0.254")]
    pub dst_ip: Ipv4Addr,

    /// Destination port number for Layer 4 (TCP/UDP).
    #[arg(long = "dest_port", default_value_t = 80)]
    pub dest_port: u16,

    /// Source MAC address to use at the Ethernet layer.
    #[arg(long = "src_mac", value_parser = parsing::parse_mac, default_value = "aa:bb:cc:dd:ee:ff")]
    pub src_mac: [u8; 6],

    /// Destination MAC address to use at the Ethernet layer.
    #[arg(long = "dst_mac", value_parser = parsing::parse_mac, default_value = "11:22:33:44:55:66")]
    pub dst_mac: [u8; 6],

    /// Layer 4 protocol to use for the probe (TCP or UDP).
    #[arg(long = "l4_protocol", value_enum, default_value_t = L4Protocol::Udp)]
    pub l4_protocol: L4Protocol,

    /// Timeout in milliseconds between probe/retry attempts.
    #[arg(long = "timeout_ms", default_value_t = 1000)]
    pub timeout_ms: u64,

    /// Path to file where debug output will be written.
    #[arg(long = "debug_file")]
    pub debug_file: Option<String>,

    /// Format for debug output file (json or pcap).
    #[arg(long = "debug_format", value_enum)]
    pub debug_format: Option<DebugFormat>,

    /// Raw 8-bit value to OR into the IPv4 header flags/bitfield.
    #[arg(long = "ip_bitfield", value_parser = parsing::parse_bitfield, default_value = "0")]
    pub ip_bitfield: u8,
}

impl Args {
    /// Validates the consistency of command-line arguments.
    pub fn validate(&self) -> Result<(), String> {
        let format = &self.debug_format;
        let file = &self.debug_file;

        match (format, file) {
            (Some(fmt), Some(f)) => {
                let path = Path::new(f);
                let extension = path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase());

                let expected = match fmt {
                    DebugFormat::Json => "json",
                    DebugFormat::Pcap => "pcap",
                };

                match extension.as_deref() {
                    Some(ext) if ext == expected => Ok(()),
                    Some(ext) => Err(format!(
                        "Debug format is '{:?}' but file has '.{}' extension. Expected '.{}'",
                        fmt, ext, expected
                    )),
                    None => Err(format!(
                        "File '{}' has no extension. Expected '.{}' for {:?} format",
                        f, expected, fmt
                    )),
                }
            }
            (None, None) => {
                Ok(())
            }
            (Some(fmt), None) => {
                Err(format!(
                    "Debug format '{:?}' specified but no debug file provided. Use --debug_file",
                    fmt
                ))
            }
            (None, Some(f)) => {
                Err(format!(
                    "Debug file '{}' specified but no debug format provided. Use --debug_format",
                    f
                ))
            }
        }
    }
}

