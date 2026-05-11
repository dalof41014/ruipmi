# ruipmi

[![Crates.io](https://img.shields.io/crates/v/ruipmi.svg)](https://crates.io/crates/ruipmi)
[![Docs.rs](https://docs.rs/ruipmi/badge.svg)](https://docs.rs/ruipmi)
[![License](https://img.shields.io/crates/l/ruipmi.svg)](https://github.com/dalof41014/ruipmi/blob/main/LICENSE-MIT)

**`ruipmi`** is a minimal asynchronous **RMCP+ IPMI client** written in Rust.
It implements the **IPMI v2.0 LAN+ session handshake** (Open Session + RAKP1–4) with full cryptographic verification, and provides encrypted message transmission over UDP using AES-CBC-128 and HMAC-SHA256 integrity/authentication.

---

## Features

* ✅ Asynchronous UDP networking (based on `tokio::net::UdpSocket`)
* ✅ Full RMCP+ session establishment with RAKP2/RAKP4 verification
* ✅ Cipher suite support:
  * Authentication: `HMAC-SHA1`, `HMAC-MD5`, `HMAC-SHA256`
  * Integrity: `HMAC-SHA1-96`, `HMAC-SHA256-128`, `HMAC-MD5-128`
  * Confidentiality: `AES-CBC-128` or `None`
* ✅ Automatic SIK / K1 / K2 derivation
* ✅ Session sequence number validation (replay protection)
* ✅ Automatic retry on UDP packet loss (up to 3 attempts)
* ✅ Session reconnect with DNS re-resolution
* ✅ Hostname DNS resolution (not just IP)
* ✅ IPMB encapsulation support (bridging to other BMCs)
* ✅ High-level API for common operations (power control, sensors, SEL, SDR, FRU)

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
        None,  // default cipher suite
        None,
        None,
    ).await?;

    client.connect().await?;

    // High-level API
    let device_id = client.get_device_id().await?;
    println!("Device ID: {:02X?}", device_id);

    let status = client.get_chassis_status().await?;
    println!("Chassis status: {:02X?}", status);

    // Or send raw commands: [netfn, cmd, data...]
    let resp = client.request(&[0x06, 0x01]).await?;

    client.close().await?;
    Ok(())
}
```

---

## API Summary

### Session Management

| Method | Description |
|--------|-------------|
| `new(host, user, pass, cipher, ch, tgt)` | Create client (supports hostname & IP) |
| `connect()` | RMCP+ handshake with full RAKP verification |
| `request(&[u8])` | Send raw IPMI command with auto-retry |
| `close()` | Gracefully close session |
| `reconnect()` | Close and re-establish session |

### High-Level Commands

| Method | Description |
|--------|-------------|
| `get_device_id()` | Get Device ID (App 0x01) |
| `get_chassis_status()` | Get Chassis Status |
| `power_on()` | Chassis power on |
| `power_off()` | Chassis power off |
| `power_cycle()` | Chassis power cycle |
| `hard_reset()` | Chassis hard reset |
| `soft_shutdown()` | ACPI soft shutdown |
| `get_sensor_reading(n)` | Get sensor reading by number |
| `get_sdr_repo_info()` | Get SDR Repository Info |
| `get_sel_info()` | Get System Event Log Info |
| `get_fru_info(id)` | Get FRU Inventory Area Info |
| `set_boot_pxe()` | Set next boot to PXE |

---

## Cipher Suites

Default cipher suite (ID 17):

| Field | Algorithm |
|-------|-----------|
| Authentication | `HMAC-SHA256` |
| Integrity | `HMAC-SHA256-128` |
| Confidentiality | `AES-CBC-128` |

Custom example:

```rust
use ruipmi::{CipherSuite, AuthAlg, IntegrityAlg, CryptAlg};

let cipher = CipherSuite {
    authentication: AuthAlg::HmacSha1,
    integrity: IntegrityAlg::HmacSha1_96,
    confidentiality: CryptAlg::None,
};
let mut client = IpmiClient::new("host", "user", "pass", Some(cipher), None, None).await?;
```

---

## Security

* **RAKP2 verification** — validates BMC knows the password (prevents MITM)
* **RAKP4 verification** — confirms SIK derivation integrity
* **Sequence number tracking** — sliding window (32) prevents replay attacks
* **HMAC integrity** — every encrypted message is authenticated

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
├── client.rs       # IpmiClient (session, retry, reconnect)
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
