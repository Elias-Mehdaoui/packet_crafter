# Packet Crafter

A Rust implementation of a network packet crafter that constructs Ethernet/IPv4/TCP/UDP packets from scratch. This tool builds complete packets with proper headers and checksums, and can export them in PCAP or JSON format for analysis.

## Building the Project

```bash
cargo build --release
```

The binary will be available at `target/release/packet_crafter`.

## Usage

Basic command structure:
```bash
cargo run -- [OPTIONS]
```

Or using the release binary:
```bash
./target/release/packet_crafter [OPTIONS]
```

### Available Options

- `--src_ip=<IPv4>` - Source IP address (default: 192.168.0.1)
- `--dst_ip=<IPv4>` - Destination IP address (default: 192.168.0.254)
- `--dest_port=<port>` - Destination port (default: 80)
- `--src_mac=<MAC>` - Source MAC address (format: aa:bb:cc:dd:ee:ff, default: aa:bb:cc:dd:ee:ff)
- `--dst_mac=<MAC>` - Destination MAC address (default: 11:22:33:44:55:66)
- `--l4_protocol=<tcp|udp>` - Layer 4 protocol (default: udp)
- `--timeout_ms=<milliseconds>` - Timeout value (default: 1000)
- `--ip_bitfield=<hex>` - IPv4 flags/fragment offset bitfield (accepts hex like 0x40 or decimal)
- `--debug_file=<path>` - Output file for debug data
- `--debug_format=<json|pcap>` - Debug output format

### Examples

```bash
# Basic packet with custom IPs
cargo run -- --src_ip=192.168.1.100 --dst_ip=10.0.0.1 --dest_port=443

# TCP packet with custom MACs
cargo run -- --l4_protocol=tcp --src_mac=00:11:22:33:44:55 --dst_mac=aa:bb:cc:dd:ee:ff

# Export to PCAP (can be opened in Wireshark)
cargo run -- --debug_file=output.pcap --debug_format=pcap

# Export to JSON
cargo run -- --debug_file=output.json --debug_format=json

# Set Don't Fragment flag (0x40)
cargo run -- --ip_bitfield=0x40 --debug_file=test.pcap --debug_format=pcap
```

## Implementation Details

### Packet Structure
The program constructs complete network packets with:
- **Layer 2 (Ethernet)**: 14-byte header with source/destination MAC and EtherType
- **Layer 3 (IPv4)**: 20-byte header with all standard fields and correct checksum
- **Layer 4 (TCP/UDP)**: TCP (20 bytes) or UDP (8 bytes) header with checksums

### Checksums
All checksums are computed correctly using the `pnet` library:
- IPv4 header checksum
- TCP/UDP checksums (including pseudo-header)

### IP Bitfield
The `--ip_bitfield` parameter sets the top byte of the IPv4 flags/fragment offset field. The top 3 bits become the flags, and the remaining 13 bits are for fragment offset.

### Output Formats
- **PCAP**: Standard packet capture format readable by Wireshark/tshark
- **JSON**: Structured output with timestamp, packet length, and hex-encoded packet data

## Testing

Run the test suite:
```bash
cargo test
```

The project includes 26 integration tests covering:
- Argument parsing and validation
- Packet construction (TCP/UDP)
- Checksum verification
- Output file generation (PCAP/JSON)
- IP bitfield manipulation

## Documentation

Generate and view the documentation:
```bash
cargo doc --open --no-deps
```

## Privileges

No special privileges required. This program only constructs packets in memory and writes them to files - it does not send packets over the network.

## Ethical Statement

This tool is for educational purposes only. I confirm that I will only run this program in authorized environments where I have explicit permission.
