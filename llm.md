# ruipmi - LLM Integration Guide

This document helps LLMs (AI assistants) understand how to use the `ruipmi` crate to interact with BMCs via IPMI.

## Installation

```toml
[dependencies]
ruipmi = "0.3"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Core Concepts

- `ruipmi` is an async IPMI v2.0 RMCP+ client over UDP port 623
- All operations require a `tokio` async runtime
- Session lifecycle: `new()` → `connect()` → `request()`/high-level API → `close()`
- Raw commands use format `&[netfn, cmd, data...]`
- Responses are `Vec<u8>` — first byte is completion code (0x00 = success)

## Public Types

```rust
use ruipmi::{IpmiClient, IpmiError, CipherSuite, AuthAlg, IntegrityAlg, CryptAlg};
```

## Basic Usage Pattern

```rust
use ruipmi::IpmiClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to BMC (supports hostname or IP)
    let mut client = IpmiClient::new("bmc-host", "admin", "password", None, None, None).await?;
    client.connect().await?;

    // Use high-level API or raw commands
    let device_id = client.get_device_id().await?;

    // Always close when done
    client.close().await?;
    Ok(())
}
```

## API Reference

### Constructor

```rust
IpmiClient::new(
    host: &str,           // BMC IP or hostname
    username: &str,       // IPMI username
    password: &str,       // IPMI password
    cipher: Option<CipherSuite>,  // None = default (cipher suite 17: SHA256+AES)
    ipmb_channel: Option<u8>,     // None = direct, Some(ch) = bridge
    ipmb_target: Option<u8>,      // None = direct, Some(addr) = bridge target
) -> Result<Self>
```

### Session Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `connect` | `async fn connect(&mut self) -> Result<()>` | Establish RMCP+ session |
| `close` | `async fn close(&mut self) -> Result<()>` | Close session gracefully |
| `reconnect` | `async fn reconnect(&mut self) -> Result<()>` | Re-establish session (re-resolves DNS) |
| `request` | `async fn request(&mut self, raw: &[u8]) -> Result<Vec<u8>>` | Send raw command with retry |

### High-Level Commands

| Method | Signature | IPMI Command |
|--------|-----------|--------------|
| `get_device_id` | `async fn get_device_id(&mut self) -> Result<Vec<u8>>` | NetFn=App(0x06), Cmd=0x01 |
| `get_chassis_status` | `async fn get_chassis_status(&mut self) -> Result<Vec<u8>>` | NetFn=Chassis(0x00), Cmd=0x01 |
| `chassis_control` | `async fn chassis_control(&mut self, control: u8) -> Result<Vec<u8>>` | NetFn=Chassis(0x00), Cmd=0x02 |
| `power_on` | `async fn power_on(&mut self) -> Result<Vec<u8>>` | Chassis Control 0x01 |
| `power_off` | `async fn power_off(&mut self) -> Result<Vec<u8>>` | Chassis Control 0x00 |
| `power_cycle` | `async fn power_cycle(&mut self) -> Result<Vec<u8>>` | Chassis Control 0x02 |
| `hard_reset` | `async fn hard_reset(&mut self) -> Result<Vec<u8>>` | Chassis Control 0x03 |
| `soft_shutdown` | `async fn soft_shutdown(&mut self) -> Result<Vec<u8>>` | Chassis Control 0x05 |
| `get_sensor_reading` | `async fn get_sensor_reading(&mut self, n: u8) -> Result<Vec<u8>>` | NetFn=SE(0x04), Cmd=0x2D |
| `get_sdr_repo_info` | `async fn get_sdr_repo_info(&mut self) -> Result<Vec<u8>>` | NetFn=Storage(0x0A), Cmd=0x20 |
| `get_sel_info` | `async fn get_sel_info(&mut self) -> Result<Vec<u8>>` | NetFn=Storage(0x0A), Cmd=0x40 |
| `get_fru_info` | `async fn get_fru_info(&mut self, fru_id: u8) -> Result<Vec<u8>>` | NetFn=Storage(0x0A), Cmd=0x10 |
| `set_boot_pxe` | `async fn set_boot_pxe(&mut self) -> Result<Vec<u8>>` | Set System Boot Options |

## Raw Command Examples

```rust
// Get Device ID
let resp = client.request(&[0x06, 0x01]).await?;

// Get Chassis Status
let resp = client.request(&[0x00, 0x01]).await?;

// Chassis Control - Power On
let resp = client.request(&[0x00, 0x02, 0x01]).await?;

// Get Sensor Reading (sensor #1)
let resp = client.request(&[0x04, 0x2D, 0x01]).await?;

// Get SEL Entry (first entry)
let resp = client.request(&[0x0A, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]).await?;

// Set Power Restore Policy (always on)
let resp = client.request(&[0x00, 0x06, 0x01]).await?;
```

## Response Parsing

All responses start with a completion code byte:
- `0x00` = success, remaining bytes are data
- Non-zero = error code per IPMI spec

```rust
let resp = client.get_chassis_status().await?;
if resp[0] == 0x00 {
    let power_on = (resp[1] & 0x01) != 0;
    println!("Power is {}", if power_on { "ON" } else { "OFF" });
}
```

## Custom Cipher Suite

```rust
use ruipmi::{CipherSuite, AuthAlg, IntegrityAlg, CryptAlg};

// Cipher suite 3 (SHA1 + SHA1-96 + AES)
let cipher = CipherSuite {
    authentication: AuthAlg::HmacSha1,
    integrity: IntegrityAlg::HmacSha1_96,
    confidentiality: CryptAlg::AesCbc128,
};

// No encryption (auth + integrity only)
let cipher = CipherSuite {
    authentication: AuthAlg::HmacSha256,
    integrity: IntegrityAlg::HmacSha256_128,
    confidentiality: CryptAlg::None,
};
```

## IPMB Bridging

For accessing satellite BMCs through a primary BMC:

```rust
// Bridge through channel 7 to target address 0x72
let mut client = IpmiClient::new("primary-bmc", "admin", "pass", None, Some(7), Some(0x72)).await?;
client.connect().await?;
// Commands are now automatically wrapped in Send Message
let resp = client.get_device_id().await?;
```

## Error Handling

```rust
use ruipmi::IpmiError;

match client.request(&[0x06, 0x01]).await {
    Ok(data) => println!("Success: {:02X?}", data),
    Err(IpmiError::Timeout) => println!("BMC did not respond"),
    Err(IpmiError::AuthFailed) => println!("Authentication/integrity check failed"),
    Err(IpmiError::BadResponse) => println!("Invalid or unexpected response"),
    Err(IpmiError::Socket(e)) => println!("Network error: {}", e),
    Err(e) => println!("Other error: {}", e),
}
```

## Common NetFn Values

| NetFn | Name | Common Commands |
|-------|------|-----------------|
| 0x00 | Chassis | Get Status (0x01), Control (0x02), Boot Options (0x08) |
| 0x04 | Sensor/Event | Get Reading (0x2D) |
| 0x06 | App | Get Device ID (0x01), Close Session (0x3C) |
| 0x0A | Storage | Get SEL Info (0x40), Get SDR Info (0x20), Get FRU (0x10) |
| 0x0C | Transport | Get/Set LAN Config |
| 0x2C | Group | OEM group commands |

## Tips for LLMs

1. Always `connect()` before sending commands
2. Always `close()` when done to free BMC session slots
3. Use `reconnect()` if the session becomes stale
4. The default cipher suite (17) works with most modern BMCs
5. Response `Vec<u8>` first byte is always the completion code
6. For bulk operations on many BMCs, create separate `IpmiClient` instances (one per BMC)
7. The library handles UDP retries automatically (3 attempts)
