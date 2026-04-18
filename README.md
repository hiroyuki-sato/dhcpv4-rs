# DHCPv4 Sans-I/O Decoder (Rust)

This is a minimal DHCPv4 decoder implemented in Rust.

It is designed as a **sans-I/O parser**, meaning it operates purely on byte slices without performing any network I/O. The goal is to keep the parsing logic simple, reusable, and easy to integrate into different environments (e.g., user space, kernel/XDP, etc.).

## Status

- This is a **learning-oriented implementation**
- Only a **minimal subset of DHCPv4** is supported
- The API is **not stable** and may change significantly

## Features

- BOOTP/DHCP fixed header parsing (`Dhcpv4Wire`)
- Basic DHCP message parsing (`Dhcpv4Message`)
- Magic cookie validation
- DHCP message type extraction (Option 53)
- Basic DHCP option parsing (TLV-based)
- Helpers for common options:
  - Requested IP Address (Option 50)
  - Server Identifier (Option 54)
  - Lease Time (Option 51)
- Uses allocation only for parsed options (`Vec`)

## Non-goals (for now)

- Full RFC compliance
- Complete option coverage
- DHCP state machine implementation
- Complete encoding/serialization
- Strict validation of all fields

## Example

```rust
use your_crate::dhcpv4::message::Dhcpv4Message;

let msg = Dhcpv4Message::decode(packet_bytes)?;

println!("{:?}", msg.message_type);

if let Some(ip) = msg.requested_ip_address() {
    println!("Requested IP: {:?}", ip);
}
```

## Design

The implementation is split into layers:

- `wire`  
  Low-level byte parsing (no semantic validation)

- `dhcpv4::option`  
  DHCP option parsing (TLV decoding)

- `dhcpv4::message`  
  Higher-level interpretation (semantic validation, message type, helpers)

This separation keeps parsing logic modular and easier to extend.

## Notes

- DHCP is built on top of BOOTP; this implementation follows that structure
- The DHCP message type is determined via **Option 53**
- The presence of DHCP is identified by the **magic cookie (`0x63825363`)**

## Future Work

- More DHCP options
- Better validation and error handling
- Iterator-based option parsing (to reduce allocation)
- Encoding improvements
- DHCPv6 support (optional)

## Disclaimer

This is not production-ready code.  
It was written for learning and experimentation purposes.

