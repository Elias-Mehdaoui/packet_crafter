# Test Overview

This document describes the test organization for the packet crafter project.

## Test Structure

All tests are organized in the `tests/` directory following Rust best practices. No tests are in `src/` files.

### Test Files

#### 1. `tests/parsing_tests.rs` (7 tests)
Tests for command-line argument parsing utilities:

- **MAC Address Parsing**
  - Valid MAC addresses (lowercase, uppercase, mixed case)
  - Invalid formats (wrong length, invalid hex characters)

- **IP Bitfield Parsing**
  - Decimal format parsing (`4`, `255`)
  - Hexadecimal format parsing (`0x04`, `0xff`)
  - Invalid values detection

#### 2. `tests/packet_tests.rs` (7 tests)
Tests for packet construction (Ethernet/IPv4/TCP/UDP):

- **UDP Packet Construction**
  - Complete packet structure verification
  - Checksum validation

- **TCP Packet Construction**
  - Header fields (SYN flag, ports, etc.)
  - Checksum validation

- **IP Bitfield**
  - Flags manipulation (Don't Fragment, etc.)

- **Edge Cases**
  - Custom addresses and ports
  - Empty payload handling

#### 3. `tests/output_tests.rs` (6 tests)
Tests for debug output (PCAP and JSON):

- **PCAP Output**
  - File creation and validation
  - Packet data integrity
  - Wireshark compatibility

- **JSON Output**
  - Valid JSON structure
  - Correct metadata (timestamp, length, hex data)

- **Protocol Support**
  - TCP and UDP packet output

#### 4. `tests/args_validation_tests.rs` (6 tests)
Tests for CLI argument validation:

- Valid combinations (format + file)
- Invalid combinations (format without file, file without format)
- File extension matching

## Running Tests

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test packet_tests

# Run with output
cargo test -- --nocapture

# Run in release mode
cargo test --release
```

## Test Coverage

Total: **26 integration tests** covering:

- ✅ MAC address parsing (valid/invalid formats)
- ✅ IP bitfield parsing (hex/decimal)
- ✅ UDP packet construction
- ✅ TCP packet construction
- ✅ IPv4 header fields and checksums
- ✅ IP bitfield flags manipulation
- ✅ PCAP file output
- ✅ JSON file output
- ✅ Command-line argument validation

## Key Features Tested

According to the specification, these tests verify:

1. **Packet Construction** - Ethernet (L2), IPv4 (L3), UDP/TCP (L4) headers
2. **Checksums** - IPv4, TCP, and UDP checksums are calculated correctly
3. **IP Bitfield** - `--ip_bitfield` manipulation works as expected
4. **MAC Addresses** - Custom `--src_mac` and `--dst_mac` support
5. **Timeout** - `--timeout_ms` parameter accepted
6. **Output Modes**:
   - `--debug_format=pcap` creates Wireshark-readable PCAP files
   - `--debug_format=json` creates JSON with hex-encoded packet data
7. **Argument Validation** - Format/file consistency checks

## Notes

- Tests use `tempfile` crate to avoid cluttering the filesystem
- Packet parsing uses `pnet` library to verify correct packet structure
- All tests are independent and can run in parallel
- No tests in `src/` files (following Rust idioms for graduate-level code)

