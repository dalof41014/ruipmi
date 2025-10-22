// src/ipmi.rs
use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngCore;
use sha1::Sha1;
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use aes::cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut};
use cbc::cipher::block_padding::NoPadding;

use log::{error, debug};

/// Constants translated and kept minimal
pub const IPMI_LANPLUS_PORT: u16 = 0x26F; // 623
pub const IPMI_CMD_TIMEOUT_SECS: f32 = 3.5;

pub const RMCP_VERSION_1: u8 = 0x06;
pub const RMCP_CLASS_IPMI: u8 = 0x07;

pub const IPMI_LANPLUS_HEADER_LEN: usize = 0x10;
pub const OFF_AUTHTYPE: usize = 0x04;
pub const OFF_PAYLOAD_TYPE: usize = 0x05;
pub const OFF_SESSION_ID: usize = 0x06;
pub const OFF_SEQUENCE_NUM: usize = 0x0A;
pub const OFF_PAYLOAD_SIZE: usize = 0x0E;
pub const OFF_PAYLOAD: usize = 0x10;

pub const PAYLOAD_TYPE_IPMI: u8 = 0x00;
pub const PAYLOAD_TYPE_RMCP_OPEN_REQUEST: u8 = 0x10;
pub const PAYLOAD_TYPE_RMCP_OPEN_RESPONSE: u8 = 0x11;
pub const PAYLOAD_TYPE_RAKP_1: u8 = 0x12;
pub const PAYLOAD_TYPE_RAKP_2: u8 = 0x13;
pub const PAYLOAD_TYPE_RAKP_3: u8 = 0x14;
pub const PAYLOAD_TYPE_RAKP_4: u8 = 0x15;

pub const IPMI_RAKP_STATUS_NO_ERRORS: u8 = 0x00;

pub const IPMI_BMC_SLAVE_ADDR: u8 = 0x20;
pub const IPMI_REMOTE_SWID: u8 = 0x81;
pub const IPMI_NETFN_APP: u8 = 0x06;
pub const IPMI_CMD_CLOSE_SESSION: u8 = 0x3C;

pub const SESSION_AUTHTYPE_RMCP_PLUS: u8 = 0x06;
pub const AES_BLOCK: usize = 16;

/// Cipher suite options (subset sufficient for default 17)
#[derive(Clone, Copy)]
pub enum AuthAlg {
    None,
    HmacSha1,
    HmacMd5,
    HmacSha256,
}

#[derive(Clone, Copy)]
pub enum IntegrityAlg {
    None,
    HmacSha1_96,
    HmacMd5_128,
    Md5_128,
    HmacSha256_128,
}

#[derive(Clone, Copy)]
pub enum CryptAlg {
    None,
    AesCbc128,
    Xrc4_128, // not implemented here
    Xrc4_40,  // not implemented here
}

#[derive(Clone, Copy)]
pub struct CipherSuite {
    pub authentication: AuthAlg,
    pub integrity: IntegrityAlg,
    pub confidentiality: CryptAlg,
}

/// Default Cipher Suite ID 17 in your original table:
/// authentication = HMAC-SHA256, integrity = HMAC-SHA256-128, confidentiality = NONE
pub const DEFAULT_CIPHER_SUITE: CipherSuite = CipherSuite {
    authentication: AuthAlg::HmacSha256,
    integrity: IntegrityAlg::HmacSha256_128,
    confidentiality: CryptAlg::AesCbc128,
};

#[derive(Error, Debug)]
pub enum IpmiError {
    #[error("socket error: {0}")]
    Socket(String),
    #[error("timeout")]
    Timeout,
    #[error("bad response")]
    BadResponse,
    #[error("cipher suite mismatch")]
    CipherMismatch,
    #[error("auth failed")]
    AuthFailed,
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
}

type Result<T> = std::result::Result<T, IpmiError>;

pub struct IpmiClient {
    /// LAN mode only in this simplified version
    hostname: String,
    username: Vec<u8>,
    password: Vec<u8>,
    cipher: CipherSuite,
    /// UDP
    sock: UdpSocket,
    peer: SocketAddr,

    /// Session variables
    out_seq: u32,
    rq_seq: u8,
    bmc_id: [u8; 4],
    console_id: [u8; 4],
    bmc_rand: [u8; 16],
    console_rand: [u8; 16],
    bmc_guid: [u8; 16],
    sik: Vec<u8>,
    k1: Vec<u8>,
    k2: [u8; 16],

    /// flags
    established: bool,
    /// IPMB options (optional)
    ipmb_channel: Option<u8>,
    ipmb_target: Option<u8>,
}

impl IpmiClient {
    /// Create client and bind an ephemeral UDP socket.
    pub async fn new(
        hostname: &str,
        username: &str,
        password: &str,
        cipher: Option<CipherSuite>,
        ipmb_channel: Option<u8>,
        ipmb_target: Option<u8>,
    ) -> Result<Self> {
        let local = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let peer = format!("{}:{}", hostname, IPMI_LANPLUS_PORT)
            .parse::<SocketAddr>()
            .map_err(|e| IpmiError::Socket(e.to_string()))?;
        let sock = UdpSocket::bind(local)
            .await
            .map_err(|e| IpmiError::Socket(e.to_string()))?;

        sock.connect(peer)
            .await
            .map_err(|e| IpmiError::Socket(e.to_string()))?;

        Ok(Self {
            hostname: hostname.to_string(),
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
            cipher: cipher.unwrap_or(DEFAULT_CIPHER_SUITE),
            sock,
            peer,

            out_seq: 0,
            rq_seq: 0,
            bmc_id: [0; 4],
            console_id: [0; 4],
            bmc_rand: [0; 16],
            console_rand: [0; 16],
            bmc_guid: [0; 16],
            sik: vec![],
            k1: vec![],
            k2: [0; 16],

            established: false,
            ipmb_channel,
            ipmb_target,
        })
    }

    /// Open RMCP+ session: Open Session → RAKP1/2/3/4
    pub async fn connect(&mut self) -> Result<()> {
        debug!("hostname {}", self.hostname);
        debug!("peer {}", self.peer);

        // 1) Open Session Request
        self.console_id = rand_bytes_4();
        let open = self.build_open_session_request();

        self.out_seq = self.out_seq.wrapping_add(1);
        self.send(&open).await?;

        let data = self.recv(1024).await?;
        debug!("recv data len={} bytes", data.len());
        debug!("recv data hex={:02X?}", &data);

        if data.len() < 18 {
            error!("Bad response: length too short");
            return Err(IpmiError::BadResponse);
        }
        if data[17] != IPMI_RAKP_STATUS_NO_ERRORS {
            error!(
                "Bad response: unexpected status = 0x{:02X}, expected 0x00",
                data[17]
            );
            return Err(IpmiError::BadResponse);
        }
        // Check cipher fields match (auth/integrity/conf)
        // These offsets follow your Python layout: payload starts at 0x10 then +{8,16,24,32}
        let off = IPMI_LANPLUS_HEADER_LEN;
        let auth = self.cipher_auth_byte();
        let integ = self.cipher_integrity_byte();
        let conf = self.cipher_conf_byte();

        if data.get(off + 16).copied() != Some(auth)
            || data.get(off + 24).copied() != Some(integ)
            || data.get(off + 32).copied() != Some(conf)
        {
            return Err(IpmiError::CipherMismatch);
        }
        self.bmc_id.copy_from_slice(&data[off + 8..off + 12]);

        debug!("self.bmc_id hex={:02X?}", self.bmc_id);

        // 2) RAKP1
        self.console_rand = rand_bytes_16();
        debug!("After rand_bytes_16 console_rand={:02X?}, bmc_id={:02X?}", self.console_rand, self.bmc_id);
        let rakp1 = self.build_rakp1();
        debug!("RAKP1 data hex={:02X?}", rakp1);
        self.send(&rakp1).await?;

        // 3) Wait RAKP2
        let data2 = self.recv(1024).await?;
        debug!("RAKP2 recv data hex={:02X?}", data2);

        if data2.len() < 18 || data2[17] != IPMI_RAKP_STATUS_NO_ERRORS {
            return Err(IpmiError::AuthFailed);
        }
        let digest_len = self.auth_digest_len();
        let off2 = IPMI_LANPLUS_HEADER_LEN;
        self.bmc_rand.copy_from_slice(&data2[off2 + 8..off2 + 24]);
        self.bmc_guid.copy_from_slice(&data2[off2 + 24..off2 + 40]);
        let _key_exchange = &data2[off2 + 40..off2 + 40 + digest_len];

        // 4) RAKP3 → derive SIK/K1/K2
        let rakp3 = self.build_rakp3()?;
        debug!("RAKP3 data hex={:02X?}", rakp3);
        self.out_seq = self.out_seq.wrapping_add(1);
        self.send(&rakp3).await?;

        // 5) Wait RAKP4
        let data4 = self.recv(1024).await?;
        debug!("RAKP4 recv data hex={:02X?}", data4);

        if data4.len() < 18 || data4[17] != IPMI_RAKP_STATUS_NO_ERRORS {
            return Err(IpmiError::AuthFailed);
        }

        self.established = true;
        Ok(())
    }

    /// Send one IPMI command [netfn, cmd, data...], return raw response (payload after completion code etc.)
    pub async fn request(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        if !self.established {
            return Err(IpmiError::InvalidState("session not established"));
        }

        // Optional: wrap to IPMB SEND_MESSAGE if channel/target provided
        let raw = if let (Some(ch), Some(target)) = (self.ipmb_channel, self.ipmb_target)
        {
            self.build_ipmb_send_message(raw, ch, target)
        } else {
            raw.to_vec()
        };

        let msg = self.build_v2_encrypted_msg(&raw)?;
        self.out_seq = self.out_seq.wrapping_add(1);
        self.rq_seq = self.rq_seq.wrapping_add(1);
        self.send(&msg).await?;

        let data = self.recv(4096).await?;
        // Verify HMAC and decrypt
        let payload = self.decode_and_decrypt(&data)?;
        Ok(payload)
    }

    /// Close session by sending Close Session command
    pub async fn close(&mut self) -> Result<()> {
        if !self.established {
            return Ok(());
        }
        let mut raw = vec![IPMI_NETFN_APP, IPMI_CMD_CLOSE_SESSION];
        raw.extend_from_slice(&self.bmc_id);
        let msg = self.build_v2_encrypted_msg(&raw)?;
        self.out_seq = self.out_seq.wrapping_add(1);
        self.rq_seq = self.rq_seq.wrapping_add(1);
        // best-effort
        let _ = self.send(&msg).await;
        self.established = false;
        Ok(())
    }

    /* ---------------------------- Low-level helpers ------------------------- */

    async fn send(&self, buf: &[u8]) -> Result<()> {
        self.sock
            .send(buf)
            .await
            .map_err(|e| IpmiError::Socket(e.to_string()))?;
        Ok(())
    }

    async fn recv(&self, cap: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; cap];
        let dur = Duration::from_secs_f32(IPMI_CMD_TIMEOUT_SECS);
        let n = timeout(dur, self.sock.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(|e| IpmiError::Socket(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn build_open_session_request(&self) -> Vec<u8> {
        // This matches your Python layout, with placeholders minimized.
        let mut buf = vec![
            RMCP_VERSION_1, 0x00, 0xFF, RMCP_CLASS_IPMI, // RMCP
            SESSION_AUTHTYPE_RMCP_PLUS,                  // authtype 0x06
            PAYLOAD_TYPE_RMCP_OPEN_REQUEST,
            0, 0, 0, 0, 0, 0, 0, 0, // sess/seq placeholder
            0x20, 0x00, // payload size (we will set below)
        ];
        // Open Session body (consoleID + cipher triples)
        // consoleID
        buf.extend_from_slice(&[0, 0, 0, 0]); // will overwrite with console_id
        // 1st: authentication alg
        buf.extend_from_slice(&[0x41, 0x42, 0x43, 0x44, 0, 0, 0, 8, 1, 0, 0, 0]);
        // 2nd: integrity alg
        buf.extend_from_slice(&[1, 0, 0, 8, 1, 0, 0, 0]);
        // 3rd: confidentiality alg
        buf.extend_from_slice(&[2, 0, 0, 8, 1, 0, 0, 0]);

        // console_id at 0x14..0x18
        buf[0x14..0x18].copy_from_slice(&self.console_id);

        // fill auth/integrity/conf bytes at 0x1C, 0x24, 0x2C like original
        buf[0x1C] = self.cipher_auth_byte();
        buf[0x24] = self.cipher_integrity_byte();
        buf[0x2C] = self.cipher_conf_byte();

        // payload size = len(body)
        let plen = buf.len() - IPMI_LANPLUS_HEADER_LEN;
        buf[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
        buf[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;
        debug!("open_session_request buf = {:02X?}", buf);
        buf
    }

    fn build_rakp1(&self) -> Vec<u8> {
        let mut buf = vec![
            RMCP_VERSION_1, 0x00, 0xFF, RMCP_CLASS_IPMI, // RMCP
            SESSION_AUTHTYPE_RMCP_PLUS,
            PAYLOAD_TYPE_RAKP_1,
            0, 0, 0, 0, 0, 0, 0, 0, // sess/seq placeholder
            0, 0, // payload size (to be set)
            0, // Message Tag
            0, 0, 0 // reserved
        ];
        // payload:
        // BMC session id (from open response)
        buf.extend_from_slice(&self.bmc_id);
        // console random (16 bytes)
        buf.extend_from_slice(&self.console_rand);
        // role (0x14 max priv), reserved, userLength
        buf.extend_from_slice(&[0x14, 0x00, 0x00, self.username.len() as u8]);
        buf.extend_from_slice(&self.username);

        // payload size
        let plen = buf.len() - IPMI_LANPLUS_HEADER_LEN;
        buf[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
        buf[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;
        buf
    }

    fn build_rakp3(&mut self) -> Result<Vec<u8>> {
        // AuthCode = HMAC(password, Rm + SIDm + ROLEm + ULEN + USERNAME)
        let mut material = Vec::with_capacity(16 + 4 + 1 + 1 + self.username.len());
        material.extend_from_slice(&self.bmc_rand);
        material.extend_from_slice(&self.console_id);
        material.push(0x14);
        material.push(self.username.len() as u8);
        material.extend_from_slice(&self.username);
        let auth = self.hmac_auth(&self.password, &material);

        // Derive SIK = HMAC(password, Rc + Rm + ROLEm + ULEN + USERNAME)
        let mut sikm = Vec::with_capacity(16 + 16 + 1 + 1 + self.username.len());
        sikm.extend_from_slice(&self.console_rand);
        sikm.extend_from_slice(&self.bmc_rand);
        sikm.push(0x14);
        sikm.push(self.username.len() as u8);
        sikm.extend_from_slice(&self.username);
        self.sik = self.hmac_auth(&self.password, &sikm);

        // K1 = HMAC(SIK, const_1), K2 = first 16 of HMAC(SIK, const_2)
        let const1 = [0x01u8; 20];
        self.k1 = self.hmac_auth(&self.sik, &const1);
        let const2 = [0x02u8; 20];
        let k2full = self.hmac_auth(&self.sik, &const2);
        self.k2.copy_from_slice(&k2full[..16]);

        // Build RAKP3 packet
        let mut buf = vec![
            RMCP_VERSION_1, 0x00, 0xFF, RMCP_CLASS_IPMI,
            SESSION_AUTHTYPE_RMCP_PLUS,
            PAYLOAD_TYPE_RAKP_3,
            0, 0, 0, 0, 0, 0, 0, 0, // sess/seq placeholders
            0, 0, // payload size
            0, // message tag
            0, // RMCP+ Status Code
            0, 0, //Reserved
        ];
        buf.extend_from_slice(&self.bmc_id);
        buf.extend_from_slice(&auth);

        let plen = buf.len() - IPMI_LANPLUS_HEADER_LEN;
        buf[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
        buf[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;
        Ok(buf)
    }

    fn build_v2_encrypted_msg(&self, raw: &[u8]) -> Result<Vec<u8>> {
        // Inner IPMI payload (plaintext)
        let payload = self.pack_ipmi_inner(raw);

        // RMCP/session header
        let mut hdr = vec![0u8; IPMI_LANPLUS_HEADER_LEN];
        hdr[0] = RMCP_VERSION_1;
        hdr[2] = 0xFF;
        hdr[3] = RMCP_CLASS_IPMI;
        hdr[OFF_AUTHTYPE] = SESSION_AUTHTYPE_RMCP_PLUS;
        // payload type with encrypt+auth bits set (0xC0)
        hdr[OFF_PAYLOAD_TYPE] = PAYLOAD_TYPE_IPMI | 0xC0;
        // session id (BMC id returned from open)
        hdr[OFF_SESSION_ID..OFF_SESSION_ID + 4].copy_from_slice(&self.bmc_id);
        // sequence (little endian)
        hdr[OFF_SEQUENCE_NUM..OFF_SEQUENCE_NUM + 4].copy_from_slice(&self.out_seq.to_le_bytes());

        // Encrypt payload
        let enc = match self.cipher.confidentiality {
            CryptAlg::None => self.encrypt_with_none(&payload),
            CryptAlg::AesCbc128 => self.encrypt_aes_cbc(&payload, &self.k2),
            _ => return Err(IpmiError::InvalidState("RC4 not implemented")),
        }?;

        let mut msg = hdr;
        msg.extend_from_slice(&enc);

        // Write payload size
        let plen = enc.len();
        msg[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
        msg[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;

        // Integrity padding to 4-byte boundary + pad_len + next_header(0x07)
        let length_before_auth = 12 + plen + 2; // session header to end + pad_len(1)+next_header(1)
        let pad_size = (4 - (length_before_auth % 4)) % 4;
        if pad_size > 0 {
            msg.extend(std::iter::repeat(0xFF).take(pad_size));
        }
        msg.push(pad_size as u8); // pad length
        msg.push(0x07); // next header

        // HMAC over [authtype..end]
        let to_auth = &msg[OFF_AUTHTYPE..];
        let mut auth = self.hmac_integrity(&self.k1, to_auth);
        // truncate by integrity alg
        let trunc = self.integrity_truncate_len();
        auth.truncate(trunc);
        msg.extend_from_slice(&auth);

        Ok(msg)
    }

    fn pack_ipmi_inner(&self, raw: &[u8]) -> Vec<u8> {
        // raw = [netfn, cmd, data...]
        let netfn = raw[0];
        let cmd = raw[1];
        let data = &raw[2..];

        // [rsAddr, (netfn<<2), csum1] + [rqAddr, (rqSeq<<2), cmd, data..., csum2]
        let mut part1 = vec![IPMI_BMC_SLAVE_ADDR, netfn << 2];
        let csum1 = ipmi_checksum(&part1);
        part1.push(csum1);

        let mut part2 = vec![IPMI_REMOTE_SWID, (self.rq_seq << 2), cmd];
        part2.extend_from_slice(data);
        let csum2 = ipmi_checksum(&part2);
        part2.push(csum2);

        [part1, part2].concat()
    }

    fn decode_and_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Validate session authtype
        if data.get(OFF_AUTHTYPE).copied() != Some(SESSION_AUTHTYPE_RMCP_PLUS) {
            return Err(IpmiError::BadResponse);
        }
        // Verify HMAC
        let auth_len = self.integrity_truncate_len();
        if data.len() < auth_len + IPMI_LANPLUS_HEADER_LEN {
            return Err(IpmiError::BadResponse);
        }
        let auth_recv = &data[data.len() - auth_len..];
        let to_auth = &data[OFF_AUTHTYPE..data.len() - auth_len];
        let mut auth_calc = self.hmac_integrity(&self.k1, to_auth);
        auth_calc.truncate(auth_len);
        if auth_calc != auth_recv {
            return Err(IpmiError::AuthFailed);
        }

        // Decrypt the payload
        let msglen =
            (data[OFF_PAYLOAD_SIZE] as usize) | ((data[OFF_PAYLOAD_SIZE + 1] as usize) << 8);
        let enc = &data[IPMI_LANPLUS_HEADER_LEN..IPMI_LANPLUS_HEADER_LEN + msglen];

        let dec = match self.cipher.confidentiality {
            CryptAlg::None => self.decrypt_with_none(enc)?,
            CryptAlg::AesCbc128 => self.decrypt_aes_cbc(enc, &self.k2)?,
            _ => return Err(IpmiError::InvalidState("RC4 not implemented")),
        };

        // Last byte is pad_len, previous pad_len bytes are 1..pad_len
        if dec.is_empty() {
            return Err(IpmiError::DecryptFailed);
        }
        let pad_len = *dec.last().unwrap() as usize;
        if dec.len() < pad_len + 1 {
            return Err(IpmiError::DecryptFailed);
        }
        if pad_len > 0 {
            let pad = &dec[dec.len() - 1 - pad_len..dec.len() - 1];
            for (i, b) in pad.iter().enumerate() {
                if *b != (i as u8 + 1) {
                    return Err(IpmiError::DecryptFailed);
                }
            }
        }
        let payload_size = dec.len() - pad_len - 1;
        let payload = &dec[..payload_size - 1]; // strip final IPMI checksum byte region as in python
        // Return content beyond netfn/csum/rqAddr/rqSeq/cmd → Python took payload_data[6:]
        if payload.len() < 6 {
            return Err(IpmiError::BadResponse);
        }
        Ok(payload[6..].to_vec())
    }

    /* ---------------------------- Crypto helpers ---------------------------- */

    /// HMAC for "auth" per authentication algorithm
    fn hmac_auth(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        match self.cipher.authentication {
            AuthAlg::HmacSha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }
            AuthAlg::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }
            AuthAlg::HmacMd5 => {
                let mut mac = Hmac::<Md5>::new_from_slice(key).unwrap();
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }
            AuthAlg::None => vec![],
        }
    }

    /// HMAC for "integrity" (same algo family as auth in your mapping)
    fn hmac_integrity(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        // Map integrity to digest family
        match self.cipher.integrity {
            IntegrityAlg::HmacSha1_96 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }
            IntegrityAlg::HmacSha256_128 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }
            IntegrityAlg::HmacMd5_128 | IntegrityAlg::Md5_128 => {
                let mut mac = Hmac::<Md5>::new_from_slice(key).unwrap();
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }
            IntegrityAlg::None => vec![],
        }
    }

    fn integrity_truncate_len(&self) -> usize {
        match self.cipher.integrity {
            IntegrityAlg::HmacSha1_96 => 12,
            IntegrityAlg::HmacSha256_128 => 16,
            IntegrityAlg::HmacMd5_128 => 16,
            IntegrityAlg::Md5_128 => 16,
            IntegrityAlg::None => 0,
        }
    }

    fn auth_digest_len(&self) -> usize {
        match self.cipher.authentication {
            AuthAlg::HmacSha1 => 20,
            AuthAlg::HmacSha256 => 32,
            AuthAlg::HmacMd5 => 16,
            AuthAlg::None => 0,
        }
    }

    fn cipher_auth_byte(&self) -> u8 {
        match self.cipher.authentication {
            AuthAlg::None => 0x00,
            AuthAlg::HmacSha1 => 0x01,
            AuthAlg::HmacMd5 => 0x02,
            AuthAlg::HmacSha256 => 0x03,
        }
    }
    fn cipher_integrity_byte(&self) -> u8 {
        match self.cipher.integrity {
            IntegrityAlg::None => 0x00,
            IntegrityAlg::HmacSha1_96 => 0x01,
            IntegrityAlg::HmacMd5_128 => 0x02,
            IntegrityAlg::Md5_128 => 0x03,
            IntegrityAlg::HmacSha256_128 => 0x04,
        }
    }
    fn cipher_conf_byte(&self) -> u8 {
        match self.cipher.confidentiality {
            CryptAlg::None => 0x00,
            CryptAlg::AesCbc128 => 0x01,
            CryptAlg::Xrc4_128 => 0x02,
            CryptAlg::Xrc4_40 => 0x03,
        }
    }

    /// AES-CBC encrypt with padding pattern (1..pad_len) + pad_len (matches your Python)
    fn encrypt_aes_cbc(&self, plain: &[u8], k2: &[u8; 16]) -> Result<Vec<u8>> {
        let pad_len = {
            let m = (plain.len() + 1) % AES_BLOCK;
            if m == 0 { 0 } else { AES_BLOCK - m }
        };
        let mut buf = plain.to_vec();
        for i in 0..pad_len {
            buf.push((i + 1) as u8);
        }
        buf.push(pad_len as u8);

        let iv = rand_bytes_16();
        let data = buf.clone();
        let mut enc = data.clone();

        let cipher = Encryptor::<Aes128>::new_from_slices(k2, &iv)
            .map_err(|_| IpmiError::InvalidState("AES init"))?;
        cipher.encrypt_padded_mut::<NoPadding>(&mut enc, data.len()).unwrap();

        let mut out = iv.to_vec();
        out.extend_from_slice(&enc);
        Ok(out)
    }

    /// "None" confidentiality: still apply padding format for consistency
    fn encrypt_with_none(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let pad_len = {
            let m = (plain.len() + 1) % AES_BLOCK;
            if m == 0 { 0 } else { AES_BLOCK - m }
        };
        let mut buf = plain.to_vec();
        for i in 0..pad_len {
            buf.push((i + 1) as u8);
        }
        buf.push(pad_len as u8);
        // No IV; return exactly padded plaintext (no header IV)
        Ok(buf)
    }

    fn decrypt_aes_cbc(&self, enc: &[u8], k2: &[u8; 16]) -> Result<Vec<u8>> {
        if enc.len() < AES_BLOCK {
            return Err(IpmiError::DecryptFailed);
        }
        let iv = &enc[..AES_BLOCK];
        let mut data = enc[AES_BLOCK..].to_vec();
        let cipher = Decryptor::<Aes128>::new_from_slices(k2, iv)
            .map_err(|_| IpmiError::InvalidState("AES init"))?;
        cipher.decrypt_padded_mut::<NoPadding>(&mut data).unwrap();
        Ok(data)
    }

    fn decrypt_with_none(&self, enc: &[u8]) -> Result<Vec<u8>> {
        // For NONE, the "enc" is just padded plaintext
        Ok(enc.to_vec())
    }

    /* ----------------------------- IPMB wrapper ----------------------------- */

    fn build_ipmb_send_message(&self, raw: &[u8], channel: u8, target: u8) -> Vec<u8> {
        // Send Message (netfn APP, cmd 0x34)
        // Track Request bit per your Python (channel | 0x40)
        let ch = channel | 0x40;
        let raw_netfn = raw[0] << 2;
        let raw_cmd = raw[1];
        let raw_data = &raw[2..];

        // checksums
        let chk1 = ipmb_checksum(&[target, raw_netfn]);
        // rqseq/rqlun = 0
        let mut body = vec![IPMI_REMOTE_SWID, 0x00, raw_cmd];
        body.extend_from_slice(raw_data);
        let chk2 = ipmb_checksum(&body);

        let mut out = vec![
            IPMI_NETFN_APP,
            0x34, // SEND_MESSAGE
            ch,
            target,
            raw_netfn,
            chk1,
            IPMI_REMOTE_SWID,
            0x00,
            raw_cmd,
        ];
        out.extend_from_slice(raw_data);
        out.push(chk2);
        out
    }
}

/* ------------------------------- Utilities -------------------------------- */

fn rand_bytes_16() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b
}
fn rand_bytes_4() -> [u8; 4] {
    let mut b = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// IPMI checksum: 0x100 - (sum & 0xFF)
fn ipmi_checksum(buf: &[u8]) -> u8 {
    let s: u16 = buf.iter().map(|&v| v as u16).sum();
    ((0x100 - (s & 0xFF)) & 0xFF) as u8
}

/// IPMB checksum: (256 - (sum % 256)) % 256
fn ipmb_checksum(data: &[u8]) -> u8 {
    ((256u16 - (data.iter().fold(0u16, |a, &b| a + b as u16) % 256)) % 256) as u8
}
