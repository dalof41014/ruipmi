use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::timeout;

use log::{debug, error, warn};

use crate::cipher::{CipherSuite, CryptAlg, DEFAULT_CIPHER_SUITE};
use crate::codec;
use crate::constants::*;
use crate::crypto::{rand_bytes_4, rand_bytes_16};
use crate::error::{IpmiError, Result};

const MAX_RETRIES: u8 = 3;
const SEQ_WINDOW: u32 = 32;

/// SOL session state, obtained from `activate_sol()`.
pub struct SolSession {
    sol_seq: u8,
    ack_seq: u8,
}

pub struct IpmiClient {
    hostname: String,
    username: Vec<u8>,
    password: Vec<u8>,
    cipher: CipherSuite,
    sock: UdpSocket,
    peer: SocketAddr,

    out_seq: u32,
    in_seq: u32,
    rq_seq: u8,
    bmc_id: [u8; 4],
    console_id: [u8; 4],
    bmc_rand: [u8; 16],
    console_rand: [u8; 16],
    bmc_guid: [u8; 16],
    sik: Vec<u8>,
    k1: Vec<u8>,
    k2: [u8; 16],

    established: bool,
    ipmb_channel: Option<u8>,
    ipmb_target: Option<u8>,
}

impl IpmiClient {
    /// Create client and bind an ephemeral UDP socket.
    /// Supports both IP addresses and hostnames (DNS resolution).
    pub async fn new(
        hostname: &str,
        username: &str,
        password: &str,
        cipher: Option<CipherSuite>,
        ipmb_channel: Option<u8>,
        ipmb_target: Option<u8>,
    ) -> Result<Self> {
        let peer = resolve_host(hostname, IPMI_LANPLUS_PORT).await?;
        let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
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
            in_seq: 0,
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
        debug!("Open Session response len={}", data.len());

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
        self.send(&rakp1).await?;

        // 3) RAKP2 — verify BMC identity
        let data2 = self.recv(1024).await?;
        debug!("RAKP2 len={}", data2.len());
        if data2.len() < 18 || data2[17] != IPMI_RAKP_STATUS_NO_ERRORS {
            return Err(IpmiError::AuthFailed);
        }
        let off2 = IPMI_LANPLUS_HEADER_LEN;
        self.bmc_rand.copy_from_slice(&data2[off2 + 8..off2 + 24]);
        self.bmc_guid.copy_from_slice(&data2[off2 + 24..off2 + 40]);
        let digest_len = self.cipher.auth_digest_len();
        let rakp2_auth_code = &data2[off2 + 40..off2 + 40 + digest_len];

        // Verify RAKP2 auth code (BMC proves it knows the password)
        codec::verify_rakp2(
            &self.cipher,
            &self.password,
            &self.console_id,
            &self.bmc_id,
            &self.console_rand,
            &self.bmc_rand,
            &self.bmc_guid,
            &self.username,
            rakp2_auth_code,
        )?;
        debug!("RAKP2 auth code verified");

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
        self.out_seq = self.out_seq.wrapping_add(1);
        self.send(&rakp3).await?;

        // 5) RAKP4 — verify integrity check value
        let data4 = self.recv(1024).await?;
        debug!("RAKP4 len={}", data4.len());
        if data4.len() < 18 || data4[17] != IPMI_RAKP_STATUS_NO_ERRORS {
            return Err(IpmiError::AuthFailed);
        }
        let off4 = IPMI_LANPLUS_HEADER_LEN;
        let icv_len = match self.cipher.authentication {
            crate::cipher::AuthAlg::HmacSha1 => 12,
            crate::cipher::AuthAlg::HmacMd5 => 16,
            crate::cipher::AuthAlg::HmacSha256 => 16,
            crate::cipher::AuthAlg::None => 0,
        };
        if icv_len > 0 {
            let rakp4_icv = &data4[off4 + 8..off4 + 8 + icv_len];
            codec::verify_rakp4(
                &self.cipher,
                &self.sik,
                &self.console_rand,
                &self.bmc_id,
                &self.bmc_guid,
                rakp4_icv,
            )?;
            debug!("RAKP4 integrity check verified");
        }

        self.out_seq = 1;
        self.in_seq = 0;
        self.established = true;
        Ok(())
    }

    /// Send one IPMI command `[netfn, cmd, data...]` with automatic retry.
    /// Returns response payload.
    pub async fn request(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        if !self.established {
            return Err(IpmiError::InvalidState("session not established"));
        }

        let raw = if let (Some(ch), Some(target)) = (self.ipmb_channel, self.ipmb_target) {
            codec::build_ipmb_send_message(raw, ch, target)
        } else {
            raw.to_vec()
        };

        for attempt in 0..MAX_RETRIES {
            let msg = codec::build_v2_encrypted_msg(
                &self.cipher, &raw, &self.bmc_id, self.out_seq, self.rq_seq, &self.k1, &self.k2,
            )?;
            self.send(&msg).await?;

            match self.recv(4096).await {
                Ok(data) => {
                    let (seq, payload) = codec::decode_and_decrypt(
                        &self.cipher, &data, &self.k1, &self.k2,
                    )?;
                    // Validate sequence number
                    if seq == 0 || (self.in_seq > 0 && seq <= self.in_seq.saturating_sub(SEQ_WINDOW)) {
                        warn!("Sequence number replay detected: got={}, last={}", seq, self.in_seq);
                        return Err(IpmiError::BadResponse);
                    }
                    if seq > self.in_seq {
                        self.in_seq = seq;
                    }
                    self.out_seq = self.out_seq.wrapping_add(1);
                    self.rq_seq = self.rq_seq.wrapping_add(1);
                    return Ok(payload);
                }
                Err(IpmiError::Timeout) if attempt < MAX_RETRIES - 1 => {
                    warn!("Timeout on attempt {}, retrying...", attempt + 1);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(IpmiError::Timeout)
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
        if self.send(&msg).await.is_ok() {
            let _ = self.recv(1024).await;
        }
        self.established = false;
        Ok(())
    }

    /// Reconnect: close existing session (if any) and establish a new one.
    pub async fn reconnect(&mut self) -> Result<()> {
        let _ = self.close().await;
        // Re-resolve DNS in case IP changed
        let peer = resolve_host(&self.hostname, IPMI_LANPLUS_PORT).await?;
        let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let sock = UdpSocket::bind(local)
            .await
            .map_err(|e| IpmiError::Socket(e.to_string()))?;
        sock.connect(peer)
            .await
            .map_err(|e| IpmiError::Socket(e.to_string()))?;
        self.sock = sock;
        self.peer = peer;
        self.out_seq = 0;
        self.in_seq = 0;
        self.rq_seq = 0;
        self.connect().await
    }

    // --- High-level IPMI commands ---

    /// Get Device ID (NetFn=App, Cmd=0x01)
    pub async fn get_device_id(&mut self) -> Result<Vec<u8>> {
        self.request(&[IPMI_NETFN_APP, 0x01]).await
    }

    /// Chassis Status (NetFn=Chassis 0x00, Cmd=0x01)
    pub async fn get_chassis_status(&mut self) -> Result<Vec<u8>> {
        self.request(&[0x00, 0x01]).await
    }

    /// Chassis Control (NetFn=Chassis 0x00, Cmd=0x02)
    /// control: 0=off, 1=on, 2=cycle, 3=hard reset, 5=soft shutdown
    pub async fn chassis_control(&mut self, control: u8) -> Result<Vec<u8>> {
        self.request(&[0x00, 0x02, control]).await
    }

    /// Power On
    pub async fn power_on(&mut self) -> Result<Vec<u8>> {
        self.chassis_control(0x01).await
    }

    /// Power Off
    pub async fn power_off(&mut self) -> Result<Vec<u8>> {
        self.chassis_control(0x00).await
    }

    /// Power Cycle
    pub async fn power_cycle(&mut self) -> Result<Vec<u8>> {
        self.chassis_control(0x02).await
    }

    /// Hard Reset
    pub async fn hard_reset(&mut self) -> Result<Vec<u8>> {
        self.chassis_control(0x03).await
    }

    /// Soft Shutdown (ACPI)
    pub async fn soft_shutdown(&mut self) -> Result<Vec<u8>> {
        self.chassis_control(0x05).await
    }

    /// Get Sensor Reading (NetFn=SE 0x04, Cmd=0x2D)
    pub async fn get_sensor_reading(&mut self, sensor_number: u8) -> Result<Vec<u8>> {
        self.request(&[0x04, 0x2D, sensor_number]).await
    }

    /// Get SDR Repository Info (NetFn=Storage 0x0A, Cmd=0x20)
    pub async fn get_sdr_repo_info(&mut self) -> Result<Vec<u8>> {
        self.request(&[0x0A, 0x20]).await
    }

    /// Get SEL Info (NetFn=Storage 0x0A, Cmd=0x40)
    pub async fn get_sel_info(&mut self) -> Result<Vec<u8>> {
        self.request(&[0x0A, 0x40]).await
    }

    /// Get FRU Inventory Area Info (NetFn=Storage 0x0A, Cmd=0x10)
    pub async fn get_fru_info(&mut self, fru_id: u8) -> Result<Vec<u8>> {
        self.request(&[0x0A, 0x10, fru_id]).await
    }

    /// Set Boot Options - force PXE boot next (NetFn=Chassis 0x00, Cmd=0x08)
    pub async fn set_boot_pxe(&mut self) -> Result<Vec<u8>> {
        // Set boot flags: valid, PXE, persistent=no
        self.request(&[0x00, 0x08, 0x05, 0x80, 0x04, 0x00, 0x00, 0x00]).await
    }

    // --- SOL (Serial over LAN) ---

    /// Activate SOL payload. Returns a `SolSession` for sending/receiving serial data.
    pub async fn activate_sol(&mut self) -> Result<SolSession> {
        if !self.established {
            return Err(IpmiError::InvalidState("session not established"));
        }
        // Deactivate any existing SOL session first (ignore errors)
        let _ = self.request(&[
            IPMI_NETFN_APP, IPMI_CMD_DEACTIVATE_PAYLOAD,
            SOL_PAYLOAD_TYPE_NUM, 0x01,
            0x00, 0x00, 0x00, 0x00,
        ]).await;

        // Activate Payload: NetFn=App(0x06), Cmd=0x48
        // aux: bit7=encrypt, bit6=auth
        let mut aux: u8 = 0x00;
        if !matches!(self.cipher.confidentiality, CryptAlg::None) {
            aux |= 0x80;
        }
        if !matches!(self.cipher.integrity, crate::cipher::IntegrityAlg::None) {
            aux |= 0x40;
        }
        let resp = self.request(&[
            IPMI_NETFN_APP, IPMI_CMD_ACTIVATE_PAYLOAD,
            SOL_PAYLOAD_TYPE_NUM, 0x01,
            aux, 0x00, 0x00, 0x00,
        ]).await?;

        if resp.is_empty() || resp[0] != 0x00 {
            return Err(IpmiError::BadResponse);
        }
        debug!("SOL activated, response: {:02X?}", resp);

        Ok(SolSession { sol_seq: 1, ack_seq: 0 })
    }

    /// Deactivate SOL payload.
    pub async fn deactivate_sol(&mut self) -> Result<()> {
        if !self.established {
            return Ok(());
        }
        let resp = self.request(&[
            IPMI_NETFN_APP, IPMI_CMD_DEACTIVATE_PAYLOAD,
            SOL_PAYLOAD_TYPE_NUM, 0x01, // payload type=SOL, instance=1
            0x00, 0x00, 0x00, 0x00,
        ]).await?;
        debug!("SOL deactivated: {:02X?}", resp);
        Ok(())
    }

    /// Send data over SOL (serial console input).
    pub async fn sol_send(&mut self, sol: &mut SolSession, data: &[u8]) -> Result<()> {
        if !self.established {
            return Err(IpmiError::InvalidState("session not established"));
        }
        let msg = codec::build_sol_packet(
            &self.cipher, data, &self.bmc_id, self.out_seq,
            sol.sol_seq, sol.ack_seq, 0, &self.k1, &self.k2,
        )?;
        self.send(&msg).await?;
        self.out_seq = self.out_seq.wrapping_add(1);
        sol.sol_seq = sol.sol_seq.wrapping_add(1);
        if sol.sol_seq == 0 { sol.sol_seq = 1; } // seq 0 is reserved
        Ok(())
    }

    /// Receive data from SOL (serial console output).
    /// Returns the received bytes, or empty vec on timeout.
    pub async fn sol_recv(&mut self, sol: &mut SolSession) -> Result<Vec<u8>> {
        if !self.established {
            return Err(IpmiError::InvalidState("session not established"));
        }
        let data = match self.recv(4096).await {
            Ok(d) => d,
            Err(IpmiError::Timeout) => return Ok(vec![]),
            Err(e) => return Err(e),
        };

        let (payload_type, seq, raw) = codec::decode_v2_payload(
            &self.cipher, &data, &self.k1, &self.k2,
        )?;

        if payload_type != PAYLOAD_TYPE_SOL {
            // Not a SOL packet, ignore
            return Ok(vec![]);
        }

        if seq > self.in_seq {
            self.in_seq = seq;
        }

        let (bmc_seq, _ack_seq, _accepted, _status, sol_data) = codec::decode_sol_payload(&raw);

        // Update ack tracking
        if bmc_seq != 0 {
            sol.ack_seq = bmc_seq;
            // Send ACK (empty data packet with ack)
            let ack = codec::build_sol_packet(
                &self.cipher, &[], &self.bmc_id, self.out_seq,
                0, sol.ack_seq, sol_data.len() as u8, &self.k1, &self.k2,
            )?;
            self.send(&ack).await?;
            self.out_seq = self.out_seq.wrapping_add(1);
        }

        Ok(sol_data)
    }

    // --- Internal helpers ---

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

/// Resolve hostname (or IP string) to SocketAddr.
async fn resolve_host(host: &str, port: u16) -> Result<SocketAddr> {
    // Try direct parse first (for IP addresses)
    if let Ok(addr) = format!("{}:{}", host, port).parse::<SocketAddr>() {
        return Ok(addr);
    }
    // DNS lookup
    let addr = lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| IpmiError::Socket(format!("DNS resolution failed: {}", e)))?
        .next()
        .ok_or_else(|| IpmiError::Socket("DNS returned no addresses".to_string()))?;
    Ok(addr)
}
