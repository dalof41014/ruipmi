use crate::cipher::{CipherSuite, CryptAlg, IntegrityAlg};
use crate::constants::*;
use crate::crypto::{decrypt, encrypt, hmac_auth, hmac_integrity};
use crate::error::{IpmiError, Result};

/// Build Open Session Request packet.
pub fn build_open_session_request(cipher: &CipherSuite, console_id: &[u8; 4]) -> Vec<u8> {
    let mut buf = vec![
        RMCP_VERSION_1, 0x00, 0xFF, RMCP_CLASS_IPMI,
        SESSION_AUTHTYPE_RMCP_PLUS,
        PAYLOAD_TYPE_RMCP_OPEN_REQUEST,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x20, 0x00,
    ];
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00]);

    buf[0x14..0x18].copy_from_slice(console_id);
    buf[0x1C] = cipher.auth_byte();
    buf[0x24] = cipher.integrity_byte();
    buf[0x2C] = cipher.conf_byte();

    let plen = buf.len() - IPMI_LANPLUS_HEADER_LEN;
    buf[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
    buf[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;
    buf
}

/// Build RAKP Message 1 packet.
pub fn build_rakp1(
    bmc_id: &[u8; 4],
    console_rand: &[u8; 16],
    username: &[u8],
) -> Vec<u8> {
    let mut buf = vec![
        RMCP_VERSION_1, 0x00, 0xFF, RMCP_CLASS_IPMI,
        SESSION_AUTHTYPE_RMCP_PLUS,
        PAYLOAD_TYPE_RAKP_1,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
        0, 0, 0, 0,
    ];
    buf.extend_from_slice(bmc_id);
    buf.extend_from_slice(console_rand);
    buf.extend_from_slice(&[0x14, 0x00, 0x00, username.len() as u8]);
    buf.extend_from_slice(username);

    let plen = buf.len() - IPMI_LANPLUS_HEADER_LEN;
    buf[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
    buf[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;
    buf
}

/// Verify RAKP2 auth code from BMC.
/// HMAC(password, SIDm || SIDc || Rm || Rc || GUIDc || ROLEm || ULENm || UNAMEm)
pub fn verify_rakp2(
    cipher: &CipherSuite,
    password: &[u8],
    console_id: &[u8; 4],
    bmc_id: &[u8; 4],
    console_rand: &[u8; 16],
    bmc_rand: &[u8; 16],
    bmc_guid: &[u8; 16],
    username: &[u8],
    received_auth_code: &[u8],
) -> Result<()> {
    let mut data = Vec::with_capacity(58 + username.len());
    data.extend_from_slice(console_id);  // SIDm
    data.extend_from_slice(bmc_id);      // SIDc
    data.extend_from_slice(console_rand); // Rm
    data.extend_from_slice(bmc_rand);    // Rc
    data.extend_from_slice(bmc_guid);    // GUIDc
    data.push(0x14);                     // ROLEm
    data.push(username.len() as u8);     // ULENGTHm
    data.extend_from_slice(username);    // UNAMEm

    let expected = hmac_auth(cipher, password, &data);
    if expected.len() < received_auth_code.len() {
        return Err(IpmiError::AuthFailed);
    }
    if expected[..received_auth_code.len()] != *received_auth_code {
        return Err(IpmiError::AuthFailed);
    }
    Ok(())
}

/// Verify RAKP4 integrity check value.
/// HMAC(SIK, Rm || SIDc || GUIDc) truncated per auth algorithm.
pub fn verify_rakp4(
    cipher: &CipherSuite,
    sik: &[u8],
    console_rand: &[u8; 16],
    bmc_id: &[u8; 4],
    bmc_guid: &[u8; 16],
    received_icv: &[u8],
) -> Result<()> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(console_rand); // Rm
    data.extend_from_slice(bmc_id);       // SIDc (BMC session ID)
    data.extend_from_slice(bmc_guid);     // GUIDc

    let full = hmac_auth(cipher, sik, &data);
    // Truncate: SHA1->12, MD5->16, SHA256->16
    let trunc_len = match cipher.authentication {
        crate::cipher::AuthAlg::HmacSha1 => 12,
        crate::cipher::AuthAlg::HmacMd5 => 16,
        crate::cipher::AuthAlg::HmacSha256 => 16,
        crate::cipher::AuthAlg::None => 0,
    };
    if trunc_len == 0 {
        return Ok(());
    }
    if received_icv.len() != trunc_len || full[..trunc_len] != *received_icv {
        return Err(IpmiError::AuthFailed);
    }
    Ok(())
}

/// Build RAKP Message 3 and derive session keys (SIK, K1, K2).
/// Returns (rakp3_packet, sik, k1, k2).
pub fn build_rakp3(
    cipher: &CipherSuite,
    password: &[u8],
    username: &[u8],
    bmc_id: &[u8; 4],
    console_id: &[u8; 4],
    console_rand: &[u8; 16],
    bmc_rand: &[u8; 16],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, [u8; 16])> {
    // AuthCode = HMAC(password, Rm + SIDm + ROLEm + ULEN + USERNAME)
    let mut material = Vec::with_capacity(16 + 4 + 2 + username.len());
    material.extend_from_slice(bmc_rand);
    material.extend_from_slice(console_id);
    material.push(0x14);
    material.push(username.len() as u8);
    material.extend_from_slice(username);
    let auth = hmac_auth(cipher, password, &material);

    // SIK = HMAC(password, Rc + Rm + ROLEm + ULEN + USERNAME)
    let mut sikm = Vec::with_capacity(32 + 2 + username.len());
    sikm.extend_from_slice(console_rand);
    sikm.extend_from_slice(bmc_rand);
    sikm.push(0x14);
    sikm.push(username.len() as u8);
    sikm.extend_from_slice(username);
    let sik = hmac_auth(cipher, password, &sikm);

    // K1 = HMAC(SIK, const_1), K2 = first 16 bytes of HMAC(SIK, const_2)
    let k1 = hmac_auth(cipher, &sik, &[0x01u8; 20]);
    let k2full = hmac_auth(cipher, &sik, &[0x02u8; 20]);
    let mut k2 = [0u8; 16];
    k2.copy_from_slice(&k2full[..16]);

    // Build packet
    let mut buf = vec![
        RMCP_VERSION_1, 0x00, 0xFF, RMCP_CLASS_IPMI,
        SESSION_AUTHTYPE_RMCP_PLUS,
        PAYLOAD_TYPE_RAKP_3,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
        0, 0, 0, 0,
    ];
    buf.extend_from_slice(bmc_id);
    buf.extend_from_slice(&auth);

    let plen = buf.len() - IPMI_LANPLUS_HEADER_LEN;
    buf[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
    buf[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;

    Ok((buf, sik, k1, k2))
}

/// Build an encrypted IPMI v2 message with integrity trailer.
pub fn build_v2_encrypted_msg(
    cipher: &CipherSuite,
    raw: &[u8],
    bmc_id: &[u8; 4],
    out_seq: u32,
    rq_seq: u8,
    k1: &[u8],
    k2: &[u8; 16],
) -> Result<Vec<u8>> {
    let payload = pack_ipmi_inner(raw, rq_seq);

    let mut hdr = vec![0u8; IPMI_LANPLUS_HEADER_LEN];
    hdr[0] = RMCP_VERSION_1;
    hdr[2] = 0xFF;
    hdr[3] = RMCP_CLASS_IPMI;
    hdr[OFF_AUTHTYPE] = SESSION_AUTHTYPE_RMCP_PLUS;

    let encrypt_bit = match cipher.confidentiality {
        CryptAlg::None => 0x00,
        _ => 0x80,
    };
    let auth_bit = match cipher.integrity {
        IntegrityAlg::None => 0x00,
        _ => 0x40,
    };
    hdr[OFF_PAYLOAD_TYPE] = PAYLOAD_TYPE_IPMI | encrypt_bit | auth_bit;
    hdr[OFF_SESSION_ID..OFF_SESSION_ID + 4].copy_from_slice(bmc_id);
    hdr[OFF_SEQUENCE_NUM..OFF_SEQUENCE_NUM + 4].copy_from_slice(&out_seq.to_le_bytes());

    let enc = encrypt(cipher, &payload, k2)?;

    let mut msg = hdr;
    msg.extend_from_slice(&enc);

    let plen = enc.len();
    msg[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
    msg[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;

    // Integrity padding
    let length_before_auth = 12 + plen + 2;
    let pad_size = (4 - (length_before_auth % 4)) % 4;
    if pad_size > 0 {
        msg.extend(std::iter::repeat(0xFF).take(pad_size));
    }
    msg.push(pad_size as u8);
    msg.push(0x07);

    // HMAC integrity
    let to_auth = &msg[OFF_AUTHTYPE..];
    let mut auth = hmac_integrity(cipher, k1, to_auth);
    auth.truncate(cipher.integrity_truncate_len());
    msg.extend_from_slice(&auth);

    Ok(msg)
}

/// Decode and decrypt an incoming IPMI v2 response. Returns (sequence_number, payload).
pub fn decode_and_decrypt(
    cipher: &CipherSuite,
    data: &[u8],
    k1: &[u8],
    k2: &[u8; 16],
) -> Result<(u32, Vec<u8>)> {
    if data.get(OFF_AUTHTYPE).copied() != Some(SESSION_AUTHTYPE_RMCP_PLUS) {
        return Err(IpmiError::BadResponse);
    }

    let auth_len = cipher.integrity_truncate_len();
    if data.len() < auth_len + IPMI_LANPLUS_HEADER_LEN {
        return Err(IpmiError::BadResponse);
    }

    // Verify HMAC
    let auth_recv = &data[data.len() - auth_len..];
    let to_auth = &data[OFF_AUTHTYPE..data.len() - auth_len];
    let mut auth_calc = hmac_integrity(cipher, k1, to_auth);
    auth_calc.truncate(auth_len);
    if auth_calc != auth_recv {
        return Err(IpmiError::AuthFailed);
    }

    // Extract sequence number
    let seq = u32::from_le_bytes([
        data[OFF_SEQUENCE_NUM],
        data[OFF_SEQUENCE_NUM + 1],
        data[OFF_SEQUENCE_NUM + 2],
        data[OFF_SEQUENCE_NUM + 3],
    ]);

    // Decrypt
    let msglen = (data[OFF_PAYLOAD_SIZE] as usize) | ((data[OFF_PAYLOAD_SIZE + 1] as usize) << 8);
    let enc = &data[IPMI_LANPLUS_HEADER_LEN..IPMI_LANPLUS_HEADER_LEN + msglen];
    let dec = decrypt(cipher, enc, k2)?;

    // Strip confidentiality padding only when encrypted
    let ipmi_payload = match cipher.confidentiality {
        CryptAlg::None => dec,
        _ => {
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
            dec[..payload_size].to_vec()
        }
    };

    // IPMI response: [rsAddr, netfn, csum1, rqAddr, rqSeq, cmd, ...data..., csum2]
    if ipmi_payload.len() < 7 {
        return Err(IpmiError::BadResponse);
    }
    Ok((seq, ipmi_payload[6..ipmi_payload.len() - 1].to_vec()))
}

/// Pack raw [netfn, cmd, data...] into IPMI inner message format.
fn pack_ipmi_inner(raw: &[u8], rq_seq: u8) -> Vec<u8> {
    let netfn = raw[0];
    let cmd = raw[1];
    let data = &raw[2..];

    let mut part1 = vec![IPMI_BMC_SLAVE_ADDR, netfn << 2];
    let csum1 = ipmi_checksum(&part1);
    part1.push(csum1);

    let mut part2 = vec![IPMI_REMOTE_SWID, rq_seq << 2, cmd];
    part2.extend_from_slice(data);
    let csum2 = ipmi_checksum(&part2);
    part2.push(csum2);

    [part1, part2].concat()
}

/// Build IPMB Send Message wrapper.
pub fn build_ipmb_send_message(raw: &[u8], channel: u8, target: u8) -> Vec<u8> {
    let ch = channel | 0x40;
    let raw_netfn = raw[0] << 2;
    let raw_cmd = raw[1];
    let raw_data = &raw[2..];

    let chk1 = ipmb_checksum(&[target, raw_netfn]);
    let mut body = vec![IPMI_REMOTE_SWID, 0x00, raw_cmd];
    body.extend_from_slice(raw_data);
    let chk2 = ipmb_checksum(&body);

    let mut out = vec![
        IPMI_NETFN_APP, 0x34, ch, target, raw_netfn, chk1,
        IPMI_REMOTE_SWID, 0x00, raw_cmd,
    ];
    out.extend_from_slice(raw_data);
    out.push(chk2);
    out
}

fn ipmi_checksum(buf: &[u8]) -> u8 {
    let s: u16 = buf.iter().map(|&v| v as u16).sum();
    ((0x100 - (s & 0xFF)) & 0xFF) as u8
}

fn ipmb_checksum(data: &[u8]) -> u8 {
    ((256u16 - (data.iter().fold(0u16, |a, &b| a + b as u16) % 256)) % 256) as u8
}

/// Build SOL data packet (payload type 0x01).
pub fn build_sol_packet(
    cipher: &CipherSuite,
    data: &[u8],
    bmc_id: &[u8; 4],
    out_seq: u32,
    sol_seq: u8,
    ack_seq: u8,
    accepted_chars: u8,
    k1: &[u8],
    k2: &[u8; 16],
) -> Result<Vec<u8>> {
    // SOL payload: [seq, ack_seq, accepted_chars, operation/status, data...]
    let mut payload = Vec::with_capacity(4 + data.len());
    payload.push(sol_seq);       // packet sequence number
    payload.push(ack_seq);       // ack/nack sequence number
    payload.push(accepted_chars); // accepted character count
    payload.push(0x00);          // operation: no flush, no break, no CTS/DCD/DSR
    payload.extend_from_slice(data);

    let mut hdr = vec![0u8; IPMI_LANPLUS_HEADER_LEN];
    hdr[0] = RMCP_VERSION_1;
    hdr[2] = 0xFF;
    hdr[3] = RMCP_CLASS_IPMI;
    hdr[OFF_AUTHTYPE] = SESSION_AUTHTYPE_RMCP_PLUS;

    let encrypt_bit = match cipher.confidentiality {
        CryptAlg::None => 0x00,
        _ => 0x80,
    };
    let auth_bit = match cipher.integrity {
        IntegrityAlg::None => 0x00,
        _ => 0x40,
    };
    hdr[OFF_PAYLOAD_TYPE] = PAYLOAD_TYPE_SOL | encrypt_bit | auth_bit;
    hdr[OFF_SESSION_ID..OFF_SESSION_ID + 4].copy_from_slice(bmc_id);
    hdr[OFF_SEQUENCE_NUM..OFF_SEQUENCE_NUM + 4].copy_from_slice(&out_seq.to_le_bytes());

    let enc = encrypt(cipher, &payload, k2)?;

    let mut msg = hdr;
    msg.extend_from_slice(&enc);

    let plen = enc.len();
    msg[OFF_PAYLOAD_SIZE] = (plen & 0xFF) as u8;
    msg[OFF_PAYLOAD_SIZE + 1] = ((plen >> 8) & 0xFF) as u8;

    // Integrity padding + HMAC
    let length_before_auth = 12 + plen + 2;
    let pad_size = (4 - (length_before_auth % 4)) % 4;
    if pad_size > 0 {
        msg.extend(std::iter::repeat(0xFF).take(pad_size));
    }
    msg.push(pad_size as u8);
    msg.push(0x07);

    let to_auth = &msg[OFF_AUTHTYPE..];
    let mut auth = hmac_integrity(cipher, k1, to_auth);
    auth.truncate(cipher.integrity_truncate_len());
    msg.extend_from_slice(&auth);

    Ok(msg)
}

/// Decode SOL response payload. Returns (sol_seq, ack_seq, accepted_chars, status, data).
pub fn decode_sol_payload(decrypted: &[u8]) -> (u8, u8, u8, u8, Vec<u8>) {
    if decrypted.len() < 4 {
        return (0, 0, 0, 0, vec![]);
    }
    let sol_seq = decrypted[0];
    let ack_seq = decrypted[1];
    let accepted = decrypted[2];
    let status = decrypted[3];
    let data = decrypted[4..].to_vec();
    (sol_seq, ack_seq, accepted, status, data)
}

/// Decode an incoming SOL or IPMI v2 packet. Returns (payload_type, sequence_number, raw_decrypted_payload).
pub fn decode_v2_payload(
    cipher: &CipherSuite,
    data: &[u8],
    k1: &[u8],
    k2: &[u8; 16],
) -> Result<(u8, u32, Vec<u8>)> {
    if data.get(OFF_AUTHTYPE).copied() != Some(SESSION_AUTHTYPE_RMCP_PLUS) {
        return Err(IpmiError::BadResponse);
    }

    let payload_type_raw = data.get(OFF_PAYLOAD_TYPE).copied().unwrap_or(0);
    let payload_type = payload_type_raw & 0x3F;

    let auth_len = cipher.integrity_truncate_len();
    if data.len() < auth_len + IPMI_LANPLUS_HEADER_LEN {
        return Err(IpmiError::BadResponse);
    }

    // Verify HMAC
    let auth_recv = &data[data.len() - auth_len..];
    let to_auth = &data[OFF_AUTHTYPE..data.len() - auth_len];
    let mut auth_calc = hmac_integrity(cipher, k1, to_auth);
    auth_calc.truncate(auth_len);
    if auth_calc != auth_recv {
        return Err(IpmiError::AuthFailed);
    }

    let seq = u32::from_le_bytes([
        data[OFF_SEQUENCE_NUM],
        data[OFF_SEQUENCE_NUM + 1],
        data[OFF_SEQUENCE_NUM + 2],
        data[OFF_SEQUENCE_NUM + 3],
    ]);

    let msglen = (data[OFF_PAYLOAD_SIZE] as usize) | ((data[OFF_PAYLOAD_SIZE + 1] as usize) << 8);
    let enc = &data[IPMI_LANPLUS_HEADER_LEN..IPMI_LANPLUS_HEADER_LEN + msglen];
    let dec = decrypt(cipher, enc, k2)?;

    // Strip confidentiality padding for encrypted payloads
    let raw = match cipher.confidentiality {
        CryptAlg::None => dec,
        _ => {
            if dec.is_empty() {
                return Err(IpmiError::DecryptFailed);
            }
            let pad_len = *dec.last().unwrap() as usize;
            if dec.len() < pad_len + 1 {
                return Err(IpmiError::DecryptFailed);
            }
            let payload_size = dec.len() - pad_len - 1;
            dec[..payload_size].to_vec()
        }
    };

    Ok((payload_type, seq, raw))
}
