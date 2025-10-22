# ruipmi

**`ruipmi`** is a minimal asynchronous **RMCP+ IPMI client** written in Rust.
It implements the **IPMI v2.0 LAN+ session handshake** (Open Session + RAKP1–4) and provides encrypted message transmission over UDP using AES-CBC-128 and HMAC-SHA256 integrity/authentication.

---

## Features

* ✅ Asynchronous UDP networking (based on `tokio::net::UdpSocket`)
* ✅ Full RMCP+ session establishment:

  * Open Session
  * RAKP 1 → 4 key exchange
* ✅ Cipher suite support:

  * Authentication: `HMAC-SHA1`, `HMAC-MD5`, `HMAC-SHA256`
  * Integrity: `HMAC-SHA1-96`, `HMAC-SHA256-128`, `HMAC-MD5-128`
  * Confidentiality: `AES-CBC-128` or `None`
* ✅ Automatic SIK / K1 / K2 derivation
* ✅ IPMB encapsulation support (for bridging to other BMCs)
* ✅ Clean modular design for embedding in higher-level management tools

---

## Architecture Overview

| Layer                    | Function                                                     |
| ------------------------ | ------------------------------------------------------------ |
| **RMCP Header**          | 4 bytes (0x06 00 FF 07)                                      |
| **RMCP+ Session Header** | 12 bytes (AuthType, PayloadType, SessionID, Seq, PayloadLen) |
| **Payload**              | Open/RAKP/IPMI command body                                  |
| **Integrity Trailer**    | Padding, Next Header, HMAC digest                            |

Internally, the client implements:

* `build_open_session_request()`
* `build_rakp1()`, `build_rakp3()`
* `build_v2_encrypted_msg()`
* `decode_and_decrypt()`

---

## Dependencies

```toml
[dependencies]
tokio = { version = "1.40", features = ["full"] }
aes = "0.8"
cbc = "0.1"
hmac = "0.12"
md-5 = "0.10"
sha1 = "0.10"
sha2 = "0.10"
rand = "0.8"
thiserror = "1.0"
log = "0.4"
```

---

## Example Usage

Create a small async test file (e.g. `examples/demo.rs`):

```rust
use ruipmi::IpmiClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = IpmiClient::new(
        "10.0.0.5",  // BMC hostname or IP
        "admin",
        "password",
        None,  // use default cipher suite
        None,
        None,
    ).await?;

    client.connect().await?;
    println!("RMCP+ session established.");

    // Example: Send Close Session command
    client.close().await?;
    println!("Session closed.");
    Ok(())
}
```

Run it:

```bash
cargo run --example demo
```

---

## API Summary

| Method                                   | Description                                             |
| ---------------------------------------- | ------------------------------------------------------- |
| `new(host, user, pass, cipher, ch, tgt)` | Create an `IpmiClient` bound to an ephemeral UDP port   |
| `connect()`                              | Perform RMCP+ session handshake (OpenSession + RAKP1–4) |
| `request(&[u8])`                         | Send one IPMI command (encrypted + HMAC verified)       |
| `close()`                                | Gracefully close the current session                    |
| `build_ipmb_send_message()`              | Wrap a raw command in IPMB SEND_MESSAGE format          |

---

## Cipher Suites

The default cipher suite matches **ID 17** from the IPMI 2.0 table:

| Field           | Algorithm         |
| --------------- | ----------------- |
| Authentication  | `HMAC-SHA256`     |
| Integrity       | `HMAC-SHA256-128` |
| Confidentiality | `AES-CBC-128`     |

To customize:

```rust
use ruipmi::{CipherSuite, AuthAlg, IntegrityAlg, CryptAlg};

let cipher = CipherSuite {
    authentication: AuthAlg::HmacSha1,
    integrity: IntegrityAlg::HmacSha1_96,
    confidentiality: CryptAlg::None,
};
let client = IpmiClient::new("host", "user", "pass", Some(cipher), None, None).await?;
```

---

## Design Notes

* Packet alignment strictly follows **IPMI v2.0 RMCP+** layout (16-byte header).
* AES encryption uses **PKCS-like padding (1..N + len)** followed by an IV prefix.
* All timeouts (`IPMI_CMD_TIMEOUT_SECS`) are enforced via `tokio::time::timeout`.
* Debug logging uses `log::debug!` and can be enabled with:

```bash
RUST_LOG=debug cargo run --example demo
```

---

## Testing

Local build and syntax check:

```bash
cargo check
cargo test
```

Run an example (requires reachable BMC endpoint):

```bash
cargo run --example demo
```

---
