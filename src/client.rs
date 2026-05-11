use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use log::{debug, error};

use crate::cipher::{CipherSuite, DEFAULT_CIPHER_SUITE};
use crate::codec;
use crate::constants::*;
use crate::crypto::rand_bytes_4;
use crate::crypto::rand_bytes_16;
use crate::error::{IpmiError, Result};

pub struct IpmiClient {
    hostname: String,
    username: Vec<u8>,
    password: Vec<u8>,
    cipher: CipherSuite,
    sock: UdpSocket,
    peer: SocketAddr,

    out_seq: u32,
    rq_seq: u8,
    bmc_id: [u8; 4],
    console_id: [u8; 4],
    bmc_rand: [u8; 16],
    console_rand: [u8; 16],
    sik: Vec<u8>,
    k1: Vec<u8>,
    k2: [u8; 16],

    established: bool,
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
        let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let peer: SocketAddr = format!("{}:{}", hostname, IPMI_LANPLUS_PORT)
            .parse()
            .map_err(|e: std::net::AddrParseError| IpmiError::Socket(e.to_string()))?;
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
            sik: vec![],
            k1: vec![],
            k2: [0; 16],
            established: false,
            ipmb_channel,
            ipmb_target,
        })
    }

    /// Perform RMCP+ session handshake (Open Session + RAKP 1-4).
    pub async fn connect(&mut self) -> Result<()> {
        debug!("hostname {}", self.hostname);
        debug!("peer {}", self.peer);

        // 1) Open Session
        self.console_id = rand_bytes_4();
        let open = codec::build_open_session_request(&self.cipher, &self.console_id);
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
            error!("Bad response: status=0x{:02X}", data[17]);
            return Err(IpmiError::BadResponse);
        }

        let off = IPMI_LANPLUS_HEADER_LEN;
        if data.get(off + 16).copied() != Some(self.cipher.auth_byte())
            || data.get(off + 24).copied() != Some(self.cipher.integrity_byte())
            || data.get(off + 32).copied() != Some(self.cipher.conf_byte())
        {
            return Err(IpmiError::CipherMismatch);
        }
        self.bmc_id.copy_from_slice(&data[off + 8..off + 12]);
        debug!("bmc_id={:02X?}", self.bmc_id);

        // 2) RAKP1
        self.console_rand = rand_bytes_16();
        let rakp1 = codec::build_rakp1(&self.bmc_id, &self.console_rand, &self.username);
        debug!("RAKP1 hex={:02X?}", rakp1);
        self.send(&rakp1).await?;

        // 3) RAKP2
        let data2 = self.recv(1024).await?;
        debug!("RAKP2 hex={:02X?}", data2);
        if data2.len() < 18 || data2[17] != IPMI_RAKP_STATUS_NO_ERRORS {
            return Err(IpmiError::AuthFailed);
        }
        let off2 = IPMI_LANPLUS_HEADER_LEN;
        self.bmc_rand.copy_from_slice(&data2[off2 + 8..off2 + 24]);

        // 4) RAKP3 + key derivation
        let (rakp3, sik, k1, k2) = codec::build_rakp3(
            &self.cipher,
            &self.password,
            &self.username,
            &self.bmc_id,
            &self.console_id,
            &self.console_rand,
            &self.bmc_rand,
        )?;
        self.sik = sik;
        self.k1 = k1;
        self.k2 = k2;
        debug!("RAKP3 hex={:02X?}", rakp3);
        self.out_seq = self.out_seq.wrapping_add(1);
        self.send(&rakp3).await?;

        // 5) RAKP4
        let data4 = self.recv(1024).await?;
        debug!("RAKP4 hex={:02X?}", data4);
        if data4.len() < 18 || data4[17] != IPMI_RAKP_STATUS_NO_ERRORS {
            return Err(IpmiError::AuthFailed);
        }

        self.established = true;
        Ok(())
    }

    /// Send one IPMI command `[netfn, cmd, data...]`, return response payload.
    pub async fn request(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        if !self.established {
            return Err(IpmiError::InvalidState("session not established"));
        }

        let raw = if let (Some(ch), Some(target)) = (self.ipmb_channel, self.ipmb_target) {
            codec::build_ipmb_send_message(raw, ch, target)
        } else {
            raw.to_vec()
        };

        let msg = codec::build_v2_encrypted_msg(
            &self.cipher, &raw, &self.bmc_id, self.out_seq, self.rq_seq, &self.k1, &self.k2,
        )?;
        self.out_seq = self.out_seq.wrapping_add(1);
        self.rq_seq = self.rq_seq.wrapping_add(1);
        self.send(&msg).await?;

        let data = self.recv(4096).await?;
        codec::decode_and_decrypt(&self.cipher, &data, &self.k1, &self.k2)
    }

    /// Gracefully close the session.
    pub async fn close(&mut self) -> Result<()> {
        if !self.established {
            return Ok(());
        }
        let mut raw = vec![IPMI_NETFN_APP, IPMI_CMD_CLOSE_SESSION];
        raw.extend_from_slice(&self.bmc_id);
        let msg = codec::build_v2_encrypted_msg(
            &self.cipher, &raw, &self.bmc_id, self.out_seq, self.rq_seq, &self.k1, &self.k2,
        )?;
        self.out_seq = self.out_seq.wrapping_add(1);
        self.rq_seq = self.rq_seq.wrapping_add(1);
        let _ = self.send(&msg).await;
        self.established = false;
        Ok(())
    }

    async fn send(&self, buf: &[u8]) -> Result<()> {
        self.sock.send(buf).await.map_err(|e| IpmiError::Socket(e.to_string()))?;
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
}
