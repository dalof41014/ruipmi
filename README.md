# ruipmi

[![Crates.io](https://img.shields.io/crates/v/ruipmi.svg)](https://crates.io/crates/ruipmi)
[![Docs.rs](https://docs.rs/ruipmi/badge.svg)](https://docs.rs/ruipmi)
[![License](https://img.shields.io/crates/l/ruipmi.svg)](https://github.com/dalof41014/ruipmi/blob/main/LICENSE-MIT)

**`ruipmi`** is a minimal asynchronous **RMCP+ IPMI client** written in Rust.
It implements the **IPMI v2.0 LAN+ session handshake** (Open Session + RAKP1–4) with full cryptographic verification, and provides encrypted message transmission over UDP.

---

## Features

- Asynchronous UDP networking (`tokio::net::UdpSocket`)
- Full RMCP+ session with **RAKP2/RAKP4 verification** (BMC identity + SIK integrity)
- Cipher suite support:
  - Authentication: `HMAC-SHA1`, `HMAC-MD5`, `HMAC-SHA256`
  - Integrity: `HMAC-SHA1-96`, `HMAC-SHA256-128`, `HMAC-MD5-128`
  - Confidentiality: `AES-CBC-128` or `None`
- Automatic SIK / K1 / K2 derivation
- Session sequence number validation (sliding window replay protection)
- Automatic retry on UDP packet loss (up to 3 attempts)
- Session reconnect with DNS re-resolution
- Hostname DNS resolution (not just IP)
- IPMB encapsulation support (bridging to other BMCs)
- High-level API for common operations

---

## Quick Start

```rust
use ruipmi::IpmiClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = IpmiClient::new(
        "10.0.0.5",  // BMC hostname or IP
        "admin",
        "password",
        None,  // default cipher suite (ID 17)
        None,  // IPMB channel
        None,  // IPMB target
    ).await?;

    client.connect().await?;

    // High-level API
    let device_id = client.get_device_id().await?;
    println!("Device ID: {:02X?}", device_id);

    let status = client.get_chassis_status().await?;
    println!("Chassis status: {:02X?}", status);

    // Raw command: [netfn, cmd, data...]
    let resp = client.request(&[0x06, 0x01]).await?;
    println!("Response: {:02X?}", resp);

    client.close().await?;
    Ok(())
}
```

---

## API

### Session Management

| Method | Description |
|--------|-------------|
| `new(host, user, pass, cipher, ch, tgt)` | Create client (supports hostname & IP) |
| `connect()` | RMCP+ handshake with RAKP2/4 verification |
| `request(&[u8])` | Send raw IPMI command with auto-retry (up to 3x) |
| `close()` | Gracefully close session (waits for BMC response) |
| `reconnect()` | Close + re-resolve DNS + re-establish session |

### High-Level Commands

| Method | Description |
|--------|-------------|
| `get_device_id()` | Get Device ID |
| `get_chassis_status()` | Get Chassis Status |
| `chassis_control(u8)` | Chassis Control (0=off, 1=on, 2=cycle, 3=reset, 5=shutdown) |
| `power_on()` | Power on |
| `power_off()` | Power off |
| `power_cycle()` | Power cycle |
| `hard_reset()` | Hard reset |
| `soft_shutdown()` | ACPI soft shutdown |
| `get_sensor_reading(n)` | Get sensor reading by number |
| `get_sdr_repo_info()` | Get SDR Repository Info |
| `get_sel_info()` | Get System Event Log Info |
| `get_fru_info(id)` | Get FRU Inventory Area Info |
| `set_boot_pxe()` | Set next boot to PXE |

### Custom Cipher Suite

```rust
use ruipmi::{CipherSuite, AuthAlg, IntegrityAlg, CryptAlg};

let cipher = CipherSuite {
    authentication: AuthAlg::HmacSha1,
    integrity: IntegrityAlg::HmacSha1_96,
    confidentiality: CryptAlg::None,
};
let mut client = IpmiClient::new("host", "user", "pass", Some(cipher), None, None).await?;
```

### IPMB Bridging

```rust
// Bridge commands through channel 7 to target 0x72
let mut client = IpmiClient::new("host", "user", "pass", None, Some(7), Some(0x72)).await?;
```

---

## Security

- **RAKP2 verification** — validates BMC knows the password (prevents MITM)
- **RAKP4 verification** — confirms SIK derivation integrity
- **Sequence number tracking** — sliding window (32) prevents replay attacks
- **HMAC integrity** — every encrypted message is authenticated

---

## Performance

Tested against a real BMC on local network:

| Metric | Result |
|--------|--------|
| Session establish | ~4ms |
| Command latency | ~2ms |
| Throughput | ~500 cmd/s |
| Reconnect | ~5ms |

---

## Project Structure

```
src/
├── lib.rs          # Public exports
├── client.rs       # IpmiClient (session, retry, reconnect, high-level API)
├── codec.rs        # Packet build/parse (RAKP, encrypted msg, IPMB)
├── crypto.rs       # HMAC & AES-CBC encryption
├── cipher.rs       # CipherSuite type definitions
├── constants.rs    # IPMI/RMCP constants
└── error.rs        # IpmiError
```

---

## Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["net", "time", "macros", "rt-multi-thread"] }
rand = "0.8"
hmac = "0.12"
sha1 = "0.10"
sha2 = "0.10"
md-5 = "0.10"
aes = "0.8"
cbc = { version = "0.1", features = ["alloc"] }
thiserror = "1"
log = "0.4"
```

---

## License

MIT OR Apache-2.0
